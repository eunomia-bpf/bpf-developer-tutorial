use super::{FindAddrOpts, SymbolInfo, SymbolType};

use std::cell::RefCell;
use std::collections::HashMap;
use std::default::Default;
use std::fs::File;
use std::io::{BufRead, BufReader, Error};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::u64;

use crate::SymResolver;

use regex::Regex;

const KALLSYMS: &str = "/proc/kallsyms";
const DFL_KSYM_CAP: usize = 200000;

pub struct Ksym {
    pub addr: u64,
    pub name: String,
}

/// The symbol resolver for /proc/kallsyms.
///
/// The users should provide the path of kallsyms, so you can provide
/// a copy from other devices.
pub struct KSymResolver {
    syms: Vec<Ksym>,
    sym_to_addr: RefCell<HashMap<&'static str, u64>>,
    file_name: PathBuf,
}

impl KSymResolver {
    pub fn new() -> KSymResolver {
        Default::default()
    }

    pub fn load_file_name(&mut self, filename: PathBuf) -> Result<(), std::io::Error> {
        let f = File::open(&filename)?;
        let mut reader = BufReader::new(f);
        let mut line = String::new();

        while let Ok(sz) = reader.read_line(&mut line) {
            if sz == 0 {
                break;
            }
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 3 {
                break;
            }
            let (addr, _symbol, func) = (tokens[0], tokens[1], tokens[2]);
            if let Ok(addr) = u64::from_str_radix(addr, 16) {
                if addr == 0 {
                    line.truncate(0);
                    continue;
                }
                let name = String::from(func);
                self.syms.push(Ksym { addr, name });
            }

            line.truncate(0);
        }

        self.syms.sort_by(|a, b| a.addr.cmp(&b.addr));

        self.file_name = filename;

        Ok(())
    }

    pub fn load(&mut self) -> Result<(), std::io::Error> {
        self.load_file_name(PathBuf::from(KALLSYMS))
    }

    fn ensure_sym_to_addr(&self) {
        if self.sym_to_addr.borrow().len() > 0 {
            return;
        }
        let mut sym_to_addr = self.sym_to_addr.borrow_mut();
        for Ksym { name, addr } in self.syms.iter() {
            // Performance & lifetime hacking
            let name_static = unsafe { &*(name as *const String) };
            sym_to_addr.insert(name_static, *addr);
        }
    }

    pub fn find_addresses_ksym(&self, addr: u64) -> impl Iterator<Item = &Ksym> {
        let mut l = 0;
        let mut r = self.syms.len();

        while l < r {
            let m = (l + r) / 2;
            let sym = &self.syms[m];

            if addr < sym.addr {
                r = m;
            } else {
                l = m + 1;
            }
        }
        debug_assert!(
            (l == 0 || l >= self.syms.len())
                || (self.syms[l - 1].addr <= addr && addr < self.syms[l].addr)
        );
        self.syms[0..l]
            .iter()
            .rev()
            .take_while(move |sym| sym.addr == self.syms[l - 1].addr)
    }

    #[cfg(test)]
    pub fn find_addresses_ksym_simple(&self, addr: u64) -> impl Iterator<Item = &Ksym> {
        let mut i = 0;
        while i < self.syms.len() && addr >= self.syms[i].addr {
            i += 1;
        }
        self.syms[..i]
            .iter()
            .rev()
            .take_while(move |x| x.addr == self.syms[i - 1].addr)
    }
}

impl Default for KSymResolver {
    fn default() -> Self {
        KSymResolver {
            syms: Vec::with_capacity(DFL_KSYM_CAP),
            sym_to_addr: RefCell::new(HashMap::new()),
            file_name: PathBuf::from(""),
        }
    }
}

impl SymResolver for KSymResolver {
    fn get_address_range(&self) -> (u64, u64) {
        (0xffffffff80000000, 0xffffffffffffffff)
    }

    fn find_symbols(&self, addr: u64) -> Vec<(&str, u64)> {
        self.find_addresses_ksym(addr)
            .map(|sym| (sym.name.as_str(), sym.addr))
            .collect()
    }

    fn find_address(&self, name: &str, opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        if let SymbolType::Variable = opts.sym_type {
            return None;
        }
        self.ensure_sym_to_addr();

        if let Some(addr) = self.sym_to_addr.borrow().get(name) {
            return Some(vec![SymbolInfo {
                name: name.to_string(),
                address: *addr,
                size: 0,
                sym_type: SymbolType::Function,
                ..Default::default()
            }]);
        }
        None
    }

    fn find_address_regex(&self, pattern: &str, opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        if let SymbolType::Variable = opts.sym_type {
            return None;
        }
        self.ensure_sym_to_addr();

        let re = Regex::new(pattern).unwrap();
        let mut syms = vec![];
        for (name, addr) in self.sym_to_addr.borrow().iter() {
            if re.is_match(name) {
                syms.push(SymbolInfo {
                    name: name.to_string(),
                    address: *addr,
                    size: 0,
                    sym_type: SymbolType::Function,
                    ..Default::default()
                });
            }
        }
        Some(syms)
    }

    fn find_line_info(&self, _addr: u64) -> Option<super::AddressLineInfo> {
        None
    }

    fn addr_file_off(&self, _addr: u64) -> Option<u64> {
        None
    }

    fn get_obj_file_name(&self) -> &Path {
        &self.file_name
    }

    fn repr(&self) -> String {
        String::from("KSymResolver")
    }
}

/// Cache of KSymResolver.
///
/// It returns the same isntance if path is the same.
pub struct KSymCache {
    resolvers: RefCell<HashMap<PathBuf, Rc<KSymResolver>>>,
}

impl KSymCache {
    pub fn new() -> KSymCache {
        KSymCache {
            resolvers: RefCell::new(HashMap::new()),
        }
    }

    /// Find an instance of KSymResolver from the cache or create a new one.
    pub fn get_resolver(&self, path: &Path) -> Result<Rc<KSymResolver>, Error> {
        let mut resolvers = self.resolvers.borrow_mut();
        if let Some(resolver) = resolvers.get(path) {
            return Ok(resolver.clone());
        }

        let mut resolver = Rc::new(KSymResolver::new());
        Rc::get_mut(&mut resolver)
            .unwrap()
            .load_file_name(path.to_path_buf())?;
        resolvers.insert(path.to_path_buf(), resolver.clone());
        Ok(resolver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    // This test case is skipped by default for /proc/kallsyms may
    // not available in some environment.
    #[test]
    #[ignore = "system-dependent; may fail"]
    fn ksym_resolver_load_find() {
        let mut resolver = KSymResolver::new();
        assert!(resolver.load().is_ok());

        assert!(
            resolver.syms.len() > 10000,
            "kallsyms seems to be unavailable or with all 0 addresses. (Check /proc/kallsyms)"
        );

        // Find the address of the symbol placed at the middle
        let sym = &resolver.syms[resolver.syms.len() / 2];
        let addr = sym.addr;
        let name = sym.name.clone();
        let found = resolver.find_symbols(addr);
        assert!(!found.is_empty());
        assert!(found.iter().any(|x| x.0 == name));
        let addr = addr + 1;
        let found = resolver.find_symbols(addr);
        assert!(!found.is_empty());
        assert!(found.iter().any(|x| x.0 == name));

        // 0 is an invalid address.  We remove all symbols with 0 as
        // thier address from the list.
        let found = resolver.find_symbols(0);
        assert!(found.is_empty());

        // Find the address of the last symbol
        let sym = &resolver.syms.last().unwrap();
        let addr = sym.addr;
        let name = sym.name.clone();
        let found = resolver.find_symbols(addr);
        assert!(!found.is_empty());
        assert!(found.iter().any(|x| x.0 == name));
        let found = resolver.find_symbols(addr + 1);
        assert!(!found.is_empty());
        assert!(found.iter().any(|x| x.0 == name));

        // Find the symbol placed at the one third
        let sym = &resolver.syms[resolver.syms.len() / 3];
        let addr = sym.addr;
        let name = sym.name.clone();
        let opts = FindAddrOpts {
            offset_in_file: false,
            obj_file_name: false,
            sym_type: SymbolType::Function,
        };
        let found = resolver.find_address(&name, &opts);
        assert!(found.is_some());
        assert!(found.unwrap().iter().any(|x| x.address == addr));
    }

    #[test]
    fn ksym_cache() {
        let cache = KSymCache::new();
        let resolver = cache.get_resolver(Path::new(KALLSYMS));
        let resolver1 = cache.get_resolver(Path::new(KALLSYMS));
        assert!(resolver.is_ok());
        assert!(resolver1.is_ok());
    }

    #[test]
    fn find_addresses_ksym() {
        let mut resolver = KSymResolver::new();
        resolver.syms = vec![
            Ksym {
                addr: 0x123,
                name: "1".to_string(),
            },
            Ksym {
                addr: 0x123,
                name: "1.5".to_string(),
            },
            Ksym {
                addr: 0x1234,
                name: "2".to_string(),
            },
            Ksym {
                addr: 0x12345,
                name: "3".to_string(),
            },
        ];

        // The address is less than the smallest address of all symbols.
        assert!(resolver.find_addresses_ksym(1).next().is_none());

        // The address match symbols exactly (the first address.)
        let syms = resolver.find_addresses_ksym(0x123).collect::<Vec<_>>();
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0].addr, 0x123);
        assert_eq!(syms[0].name, "1.5");
        assert_eq!(syms[1].addr, 0x123);
        assert_eq!(syms[1].name, "1");

        // The address is in between two symbols (the first address.)
        let syms = resolver.find_addresses_ksym(0x124).collect::<Vec<_>>();
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0].addr, 0x123);
        assert_eq!(syms[0].name, "1.5");
        assert_eq!(syms[1].addr, 0x123);
        assert_eq!(syms[1].name, "1");

        // The address match symbols exactly.
        let syms = resolver.find_addresses_ksym(0x1234).collect::<Vec<_>>();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].addr, 0x1234);
        assert_eq!(syms[0].name, "2");

        // The address is in between two symbols.
        let syms = resolver.find_addresses_ksym(0x1235).collect::<Vec<_>>();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].addr, 0x1234);
        assert_eq!(syms[0].name, "2");

        // The address match symbols exactly (the biggest address.)
        let syms = resolver.find_addresses_ksym(0x12345).collect::<Vec<_>>();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].addr, 0x12345);
        assert_eq!(syms[0].name, "3");

        // The address is bigger than the biggest address of all symbols.
        let syms = resolver.find_addresses_ksym(0x1234568).collect::<Vec<_>>();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].addr, 0x12345);
        assert_eq!(syms[0].name, "3");
    }

    #[test]
    fn find_addresses_ksym_exhaust() {
        let syms_sz = 10;
        let mut resolver = KSymResolver::new();
        resolver.syms = (0..syms_sz)
            .map(|x| Ksym {
                addr: 1,
                name: x.to_string(),
            })
            .collect();
        // A full-adder has a carry-out signal, right?
        // Yes! Here it is.
        let raised_carry_out = |addr| addr > syms_sz as u64;

        while !raised_carry_out(resolver.syms[0].addr) {
            // Test find_addresses_ksym() against every address in the
            // range [0..syms_sz+1].
            for i in 0..=(syms_sz + 1) {
                let result: Vec<_> = resolver.find_addresses_ksym(i as u64).collect();
                let result_s: Vec<_> = resolver.find_addresses_ksym_simple(i as u64).collect();
                assert_eq!(result.len(), result_s.len());
                assert_eq!(
                    result
                        .iter()
                        .map(|x| x.name.as_str())
                        .cmp(result_s.iter().map(|x| x.name.as_str())),
                    Ordering::Equal
                );
            }

            let mut i = syms_sz - 1;
            // Increase the address of the last symbol.
            resolver.syms[i].addr += 1;
            while i > 0 && raised_carry_out(resolver.syms[i].addr) {
                // Bring the raised carry-out it to the left.
                i -= 1;
                resolver.syms[i].addr += 1;
            }
            // Every symbol on the right side have a raised carry-out.
            // Reset their addresses.
            let low_addr = resolver.syms[i].addr;
            while i < (syms_sz - 1) {
                i += 1;
                resolver.syms[i].addr = low_addr;
            }
        }
    }
}
