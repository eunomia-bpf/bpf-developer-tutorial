// A library symbolizes addresses to symbols, filenames, and line numbers.
//
// BlazeSym is a library to symbolize addresses to get symbol names, file
// names of source files, and line numbers.  It can translate a stack
// trace to function names and their locations in the
// source code.
#![doc = include_str!("../README.md")]
#![allow(clippy::let_and_return, clippy::let_unit_value)]
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(feature = "nightly", feature(test))]

#[cfg(feature = "nightly")]
extern crate test;

use std::io::{Error, ErrorKind};
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::rc::Rc;
use std::u64;

use nix::sys::stat::stat;
use nix::sys::utsname;

mod c_api;
mod dwarf;
mod elf;
mod gsym;
mod ksym;
mod util;

use elf::ElfCache;
use elf::ElfResolver;
use gsym::GsymResolver;
use ksym::{KSymCache, KSymResolver};

#[cfg(doc)]
pub use c_api::*;

struct CacheHolder {
    ksym: KSymCache,
    elf: ElfCache,
}

struct CacheHolderOpts {
    line_number_info: bool,
    debug_info_symbols: bool,
}

impl CacheHolder {
    fn new(opts: CacheHolderOpts) -> CacheHolder {
        CacheHolder {
            ksym: ksym::KSymCache::new(),
            elf: ElfCache::new(opts.line_number_info, opts.debug_info_symbols),
        }
    }

    fn get_ksym_cache(&self) -> &KSymCache {
        &self.ksym
    }

    fn get_elf_cache(&self) -> &ElfCache {
        &self.elf
    }
}

trait StackFrame {
    fn get_ip(&self) -> u64;
    fn get_frame_pointer(&self) -> u64;
}

trait StackSession {
    fn next_frame(&mut self) -> Option<&dyn StackFrame>;
    fn prev_frame(&mut self) -> Option<&dyn StackFrame>;
    fn go_top(&mut self);
}

struct AddressLineInfo {
    pub path: String,
    pub line_no: usize,
    pub column: usize,
}

/// Types of symbols..
#[derive(Clone, Copy)]
pub enum SymbolType {
    Unknown,
    Function,
    Variable,
}

/// The context of an address finding request.
///
/// This type passes additional parameters to resolvers.
#[doc(hidden)]
pub struct FindAddrOpts {
    /// Return the offset of the symbol from the first byte of the
    /// object file if it is true. (False by default)
    offset_in_file: bool,
    /// Return the name of the object file if it is true. (False by default)
    obj_file_name: bool,
    /// Return the symbol(s) matching a given type. Unknown, by default, mean all types.
    sym_type: SymbolType,
}

/// Information of a symbol.
pub struct SymbolInfo {
    /// The name of the symbol; for example, a function name.
    pub name: String,
    /// Start address (the first byte) of the symbol
    pub address: u64,
    /// The size of the symbol. The size of a function for example.
    pub size: u64,
    /// A function or a variable.
    pub sym_type: SymbolType,
    /// The offset in the object file.
    pub file_offset: u64,
    /// The file name of the shared object.
    pub obj_file_name: Option<PathBuf>,
}

impl Default for SymbolInfo {
    fn default() -> Self {
        SymbolInfo {
            name: "".to_string(),
            address: 0,
            size: 0,
            sym_type: SymbolType::Unknown,
            file_offset: 0,
            obj_file_name: None,
        }
    }
}

/// The trait of symbol resolvers.
///
/// An symbol resolver usually provides information from one symbol
/// source; e., a symbol file.
trait SymResolver {
    /// Return the range that this resolver serve in an address space.
    fn get_address_range(&self) -> (u64, u64);
    /// Find the names and the start addresses of a symbol found for
    /// the given address.
    fn find_symbols(&self, addr: u64) -> Vec<(&str, u64)>;
    /// Find the address and size of a symbol name.
    fn find_address(&self, name: &str, opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>>;
    /// Find the addresses and sizes of the symbols matching a given pattern.
    fn find_address_regex(&self, pattern: &str, opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>>;
    /// Find the file name and the line number of an address.
    fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo>;
    /// Translate an address (virtual) in a process to the file offset
    /// in the object file.
    fn addr_file_off(&self, addr: u64) -> Option<u64>;
    /// Get the file name of the shared object.
    fn get_obj_file_name(&self) -> &Path;

    fn repr(&self) -> String;
}

const REG_RBP: usize = 7;
const REG_RIP: usize = 16;

struct X86_64StackFrame {
    rip: u64,
    rbp: u64,
}

impl StackFrame for X86_64StackFrame {
    fn get_ip(&self) -> u64 {
        self.rip
    }
    fn get_frame_pointer(&self) -> u64 {
        self.rbp
    }
}

/// Do stacking unwind for x86_64
///
/// Parse a block of memory that is a copy of stack of thread to get frames.
///
struct X86_64StackSession {
    frames: Vec<X86_64StackFrame>,
    stack: Vec<u8>,
    stack_base: u64, // The base address of the stack
    registers: [u64; 17],
    current_rbp: u64,
    current_rip: u64,
    current_frame_idx: usize,
}

impl X86_64StackSession {
    fn _get_rbp_rel(&self) -> usize {
        (self.current_rbp - self.stack_base) as usize
    }

    fn _mark_at_bottom(&mut self) {
        self.current_rbp = 0;
    }

    fn _is_at_bottom(&self) -> bool {
        self.current_rbp == 0
    }

    fn _get_u64(&self, off: usize) -> u64 {
        let stack = &self.stack;
        (stack[off] as u64)
            | ((stack[off + 1] as u64) << 8)
            | ((stack[off + 2] as u64) << 16)
            | ((stack[off + 3] as u64) << 24)
            | ((stack[off + 4] as u64) << 32)
            | ((stack[off + 5] as u64) << 40)
            | ((stack[off + 6] as u64) << 48)
            | ((stack[off + 7] as u64) << 56)
    }

    #[cfg(test)]
    pub fn new(stack: Vec<u8>, stack_base: u64, registers: [u64; 17]) -> X86_64StackSession {
        X86_64StackSession {
            frames: Vec::new(),
            stack,
            stack_base,
            registers,
            current_rbp: registers[REG_RBP],
            current_rip: registers[REG_RIP],
            current_frame_idx: 0,
        }
    }
}

impl StackSession for X86_64StackSession {
    fn next_frame(&mut self) -> Option<&dyn StackFrame> {
        if self._is_at_bottom() {
            return None;
        }

        if self.frames.len() > self.current_frame_idx {
            let frame = &self.frames[self.current_frame_idx];
            self.current_frame_idx += 1;
            return Some(frame);
        }

        let frame = X86_64StackFrame {
            rip: self.current_rip,
            rbp: self.current_rbp,
        };
        self.frames.push(frame);

        if self._get_rbp_rel() <= (self.stack.len() - 16) {
            let new_rbp = self._get_u64(self._get_rbp_rel());
            let new_rip = self._get_u64(self._get_rbp_rel() + 8);
            self.current_rbp = new_rbp;
            self.current_rip = new_rip;
        } else {
            self._mark_at_bottom();
        }

        self.current_frame_idx += 1;
        Some(self.frames.last().unwrap() as &dyn StackFrame)
    }

    fn prev_frame(&mut self) -> Option<&dyn StackFrame> {
        if self.current_frame_idx == 0 {
            return None;
        }

        self.current_frame_idx -= 1;
        Some(&self.frames[self.current_frame_idx] as &dyn StackFrame)
    }

    fn go_top(&mut self) {
        self.current_rip = self.registers[REG_RIP];
        self.current_rbp = self.registers[REG_RBP];
        self.current_frame_idx = 0;
    }
}

/// Create a KSymResolver
///
/// # Safety
///
/// This function is supposed to be used by C code.  The pointer
/// returned should be free with `sym_resolver_free()`.
///
#[no_mangle]
#[doc(hidden)]
pub unsafe extern "C" fn sym_resolver_create() -> *mut KSymResolver {
    let mut resolver = Box::new(KSymResolver::new());
    if resolver.load().is_err() {
        ptr::null_mut()
    } else {
        Box::leak(resolver)
    }
}


struct KernelResolver {
    ksymresolver: Option<Rc<KSymResolver>>,
    kernelresolver: Option<ElfResolver>,
    kallsyms: PathBuf,
    kernel_image: PathBuf,
}

impl KernelResolver {
    fn new(
        kallsyms: &Path,
        kernel_image: &Path,
        cache_holder: &CacheHolder,
    ) -> Result<KernelResolver, Error> {
        let ksymresolver = cache_holder.get_ksym_cache().get_resolver(kallsyms);
        let kernelresolver = ElfResolver::new(kernel_image, 0, cache_holder);

        if ksymresolver.is_err() && kernelresolver.is_err() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!(
                    "can not load {} and {}",
                    kallsyms.display(),
                    kernel_image.display()
                ),
            ));
        }

        Ok(KernelResolver {
            ksymresolver: ksymresolver.ok(),
            kernelresolver: kernelresolver.ok(),
            kallsyms: kallsyms.to_path_buf(),
            kernel_image: kernel_image.to_path_buf(),
        })
    }
}

impl SymResolver for KernelResolver {
    fn get_address_range(&self) -> (u64, u64) {
        (0xffffffff80000000, 0xffffffffffffffff)
    }

    fn find_symbols(&self, addr: u64) -> Vec<(&str, u64)> {
        if self.ksymresolver.is_some() {
            self.ksymresolver.as_ref().unwrap().find_symbols(addr)
        } else {
            self.kernelresolver.as_ref().unwrap().find_symbols(addr)
        }
    }
    fn find_address(&self, _name: &str, _opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        None
    }
    fn find_address_regex(&self, _name: &str, _opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        None
    }
    fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo> {
        self.kernelresolver.as_ref()?;
        self.kernelresolver.as_ref().unwrap().find_line_info(addr)
    }

    fn addr_file_off(&self, _addr: u64) -> Option<u64> {
        None
    }

    fn get_obj_file_name(&self) -> &Path {
        &self.kernel_image
    }

    fn repr(&self) -> String {
        format!(
            "KernelResolver {} {}",
            self.kallsyms.display(),
            self.kernel_image.display()
        )
    }
}

/// The description of a source of symbols and debug information.
///
/// The source of symbols and debug information can be an ELF file, kernel
/// image, or process.
#[derive(Clone)]
pub enum SymbolSrcCfg {
    /// A single ELF file
    ///
    /// You should provide the name of an ELF file and its base address.
    ///
    Elf {
        /// The name of ELF files.
        ///
        /// It can be an executable or shared object.
        /// For example, passing `"/bin/sh"` will load symbols and debug information from `sh`.
        /// Whereas passing `"/lib/libc.so.xxx"` will load symbols and debug information from the libc.
        file_name: PathBuf,
        /// The address where the executable segment loaded.
        ///
        /// The address in the process should be the executable segment's
        /// first byte.  For example, in `/proc/<pid>/maps`.
        ///
        /// ```text
        ///     7fe1b2dc4000-7fe1b2f80000 r-xp 00000000 00:1d 71695032                   /usr/lib64/libc-2.28.so
        ///     7fe1b2f80000-7fe1b3180000 ---p 001bc000 00:1d 71695032                   /usr/lib64/libc-2.28.so
        ///     7fe1b3180000-7fe1b3184000 r--p 001bc000 00:1d 71695032                   /usr/lib64/libc-2.28.so
        ///     7fe1b3184000-7fe1b3186000 rw-p 001c0000 00:1d 71695032                   /usr/lib64/libc-2.28.so
        /// ```
        ///
        /// It reveals that the executable segment of libc-2.28.so was
        /// loaded at 0x7fe1b2dc4000.  This base address is used to
        /// translate an address in the segment to the corresponding
        /// address in the ELF file.
        ///
        /// A loader would load an executable segment with the permission of
        /// `x`.  For example, the first block is with the permission of
        /// `r-xp`.
        base_address: u64,
    },
    /// Linux Kernel's binary image and a copy of /proc/kallsyms
    Kernel {
        /// The path of a kallsyms copy.
        ///
        /// For the running kernel on the device, it can be
        /// "/proc/kallsyms".  However, you can make a copy for later.
        /// In that situation, you should give the path of the
        /// copy.  Passing `None`, by default, will be
        /// `"/proc/kallsyms"`.
        kallsyms: Option<PathBuf>,
        /// The path of a kernel image.
        ///
        /// This should be the path of a kernel image.  For example,
        /// `"/boot/vmlinux-xxxx"`.  A `None` value will find the
        /// kernel image of the running kernel in `"/boot/"` or
        /// `"/usr/lib/debug/boot/"`.
        kernel_image: Option<PathBuf>,
    },
    /// This one will be expended into all ELF files in a process.
    ///
    /// With a `None` value, it would means a process calling BlazeSym.
    Process { pid: Option<u32> },
    Gsym {
        file_name: PathBuf,
        base_address: u64,
    },
}

/// The result of symbolization by BlazeSymbolizer.
///
/// [`BlazeSymbolizer::symbolize()`] returns a list of lists of
/// `SymbolizedResult`.  It appears as `[[SymbolizedResult {...},
/// SymbolizedResult {...}, ...], [SymbolizedResult {...}, ...],
/// ...]`.  At the first level, each entry is a list of
/// `SymbolizedResult`.  [`BlazeSymbolizer::symbolize()`] can return
/// multiple results of an address due to compiler optimizations.
#[derive(Clone)]
pub struct SymbolizedResult {
    /// The symbol name that an address may belong to.
    pub symbol: String,
    /// The address where the symbol is located within the process.
    ///
    /// The address is in the target process, not the offset from the
    /// shared object file.
    pub start_address: u64,
    /// The source path that defines the symbol.
    pub path: String,
    /// The line number of the symbolized instruction in the source code.
    ///
    /// This is the line number of the instruction of the address being
    /// symbolized, not the line number that defines the symbol
    /// (function).
    pub line_no: usize,
    pub column: usize,
}

type ResolverList = Vec<((u64, u64), Box<dyn SymResolver>)>;

struct ResolverMap {
    resolvers: ResolverList,
}

impl ResolverMap {
    fn build_resolvers_proc_maps(
        pid: u32,
        resolvers: &mut ResolverList,
        cache_holder: &CacheHolder,
    ) -> Result<(), Error> {
        let entries = util::parse_maps(pid)?;

        for entry in entries.iter() {
            if entry.path.as_path().components().next() != Some(Component::RootDir) {
                continue;
            }
            if (entry.mode & 0xa) != 0xa {
                // r-x-
                continue;
            }

            if let Ok(filestat) = stat(&entry.path) {
                if (filestat.st_mode & 0o170000) != 0o100000 {
                    // Not a regular file
                    continue;
                }
            } else {
                continue;
            }
            if let Ok(resolver) = ElfResolver::new(&entry.path, entry.loaded_address, cache_holder)
            {
                resolvers.push((resolver.get_address_range(), Box::new(resolver)));
            } else {
                #[cfg(debug_assertions)]
                eprintln!("Fail to create ElfResolver for {}", entry.path.display());
            }
        }

        Ok(())
    }

    pub fn new(
        sym_srcs: &[SymbolSrcCfg],
        cache_holder: &CacheHolder,
    ) -> Result<ResolverMap, Error> {
        let mut resolvers = ResolverList::new();
        for cfg in sym_srcs {
            match cfg {
                SymbolSrcCfg::Elf {
                    file_name,
                    base_address,
                } => {
                    let resolver = ElfResolver::new(file_name, *base_address, cache_holder)?;
                    resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                }
                SymbolSrcCfg::Kernel {
                    kallsyms,
                    kernel_image,
                } => {
                    let kallsyms = kallsyms
                        .as_deref()
                        .unwrap_or_else(|| Path::new("/proc/kallsyms"));
                    let kernel_image = if let Some(img) = kernel_image {
                        img.clone()
                    } else {
                        let release = utsname::uname()?.release().to_str().unwrap().to_string();
                        let basename = "vmlinux-";
                        let dirs = [Path::new("/boot/"), Path::new("/usr/lib/debug/boot/")];
                        let mut i = 0;
                        let kernel_image = loop {
                            let path = dirs[i].join(format!("{basename}{release}"));
                            if stat(&path).is_ok() {
                                break path;
                            }
                            i += 1;
                            if i >= dirs.len() {
                                break path;
                            }
                        };
                        kernel_image
                    };
                    if let Ok(resolver) = KernelResolver::new(kallsyms, &kernel_image, cache_holder)
                    {
                        resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                    } else {
                        #[cfg(debug_assertions)]
                        eprintln!("fail to load the kernel image {}", kernel_image.display());
                    }
                }
                SymbolSrcCfg::Process { pid } => {
                    let pid = if let Some(p) = pid { *p } else { 0 };

                    if let Err(_e) =
                        Self::build_resolvers_proc_maps(pid, &mut resolvers, cache_holder)
                    {
                        #[cfg(debug_assertions)]
                        eprintln!("Fail to load symbols for the process {pid}: {_e:?}");
                    }
                }
                SymbolSrcCfg::Gsym {
                    file_name,
                    base_address,
                } => {
                    let resolver = GsymResolver::new(file_name.clone(), *base_address)?;
                    resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                }
            };
        }
        resolvers.sort_by_key(|x| x.0 .0); // sorted by the loaded addresses

        Ok(ResolverMap { resolvers })
    }

    pub fn find_resolver(&self, address: u64) -> Option<&dyn SymResolver> {
        let idx =
            util::search_address_key(&self.resolvers, address, &|map: &(
                (u64, u64),
                Box<dyn SymResolver>,
            )|
             -> u64 { map.0 .0 })?;
        let (loaded_begin, loaded_end) = self.resolvers[idx].0;
        if loaded_begin != loaded_end && address >= loaded_end {
            // `begin == end` means this ELF file may have only
            // symbols and debug information.  For this case, we
            // always use this resolver if the given address is just
            // above its loaded address.
            None
        } else {
            Some(self.resolvers[idx].1.as_ref())
        }
    }
}

/// Switches in the features of BlazeSymbolizer.
///
/// Passing variants of this `enum` to [`BlazeSymbolizer::new_opt()`]
/// will enable (true) or disable (false) respective features
/// of a symbolizer.
pub enum SymbolizerFeature {
    /// Switch on or off the feature of returning file names and line numbers of addresses.
    ///
    /// By default, it is true.  However, if it is false,
    /// the symbolizer will not return the line number information.
    LineNumberInfo(bool), // default is true.
    /// Switch on or off the feature of parsing symbols (subprogram) from DWARF.
    ///
    /// By default, it is false.  BlazeSym parses symbols from DWARF
    /// only if the user of BlazeSym enables it.
    DebugInfoSymbols(bool),
}

/// Switches and settings of features to modify the way looking up addresses of
/// symbols or the returned information.
pub enum FindAddrFeature {
    /// Return the offset in the file.
    ///
    /// The offset will be returned as the value of `SymbolInfo::file_offset`.
    /// (Off by default)
    OffsetInFile(bool),
    /// Return the file name of the shared object.
    ///
    /// The name of the executiable or object file will be returned as
    /// the value of `SymbolInfo::obj_file_name`.
    /// (Off by default)
    ObjFileName(bool),
    /// Return symbols having the given type.
    ///
    /// With `SymbolType::Function`, BlazeSym will return only the
    /// symbols that are functions.  With `SymbolType::Variable`,
    /// BlazeSym will return only the symbols that are variables.
    /// With `SymbolType::Unknown`, BlazeSym will return symbols of
    /// any type.
    SymbolType(SymbolType),
    /// Return symbols from the compile unit (source) of the given name.
    CommpileUnit(String),
}

/// BlazeSymbolizer provides an interface to symbolize addresses with
/// a list of symbol sources.
///
/// Users should present BlazeSymbolizer with a list of symbol sources
/// (`SymbolSrcCfg`); for example, an ELF file and its base address
/// (`SymbolSrcCfg::Elf`), or a Linux kernel image and a copy of its
/// kallsyms (`SymbolSrcCfg::Kernel`).  Additionally, BlazeSymbolizer
/// uses information from these sources to symbolize addresses.
pub struct BlazeSymbolizer {
    cache_holder: CacheHolder,

    line_number_info: bool,
}

impl BlazeSymbolizer {
    /// Create and return an instance of BlazeSymbolizer.
    pub fn new() -> Result<BlazeSymbolizer, Error> {
        let opts = CacheHolderOpts {
            line_number_info: true,
            debug_info_symbols: false,
        };
        let cache_holder = CacheHolder::new(opts);

        Ok(BlazeSymbolizer {
            cache_holder,
            line_number_info: true,
        })
    }

    /// Create and return an instance of BlazeSymbolizer.
    ///
    /// `new_opt()` works like [`BlazeSymbolizer::new()`] except it receives a list of
    /// [`SymbolizerFeature`] to turn on or off some features.
    pub fn new_opt(features: &[SymbolizerFeature]) -> Result<BlazeSymbolizer, Error> {
        let mut line_number_info = true;
        let mut debug_info_symbols = false;

        for feature in features {
            match feature {
                SymbolizerFeature::LineNumberInfo(enabled) => {
                    line_number_info = *enabled;
                }
                SymbolizerFeature::DebugInfoSymbols(enabled) => {
                    debug_info_symbols = *enabled;
                }
            }
        }

        let cache_holder = CacheHolder::new(CacheHolderOpts {
            line_number_info,
            debug_info_symbols,
        });

        Ok(BlazeSymbolizer {
            cache_holder,
            line_number_info,
        })
    }

    fn find_addr_features_context(features: Vec<FindAddrFeature>) -> FindAddrOpts {
        let mut opts = FindAddrOpts {
            offset_in_file: false,
            obj_file_name: false,
            sym_type: SymbolType::Unknown,
        };
        for f in features {
            match f {
                FindAddrFeature::OffsetInFile(enable) => {
                    opts.offset_in_file = enable;
                }
                FindAddrFeature::ObjFileName(enable) => {
                    opts.obj_file_name = enable;
                }
                FindAddrFeature::SymbolType(sym_type) => {
                    opts.sym_type = sym_type;
                }
                _ => {
                    todo!();
                }
            }
        }
        opts
    }

    /// Find the addresses of the symbols matching a pattern.
    ///
    /// Find the addresses of the symbols matching a pattern from the sources
    /// of symbols and debug info described by `sym_srcs`.
    /// `find_address_regex_opt()` works just like `find_address_regex()` with
    /// additional controls on features.
    ///
    /// # Arguments
    ///
    /// * `sym_srcs` - A list of symbol and debug sources.
    /// * `pattern` - A regex pattern.
    /// * `features` - a list of `FindAddrFeature` to enable, disable, or specify parameters.
    pub fn find_address_regex_opt(
        &self,
        sym_srcs: &[SymbolSrcCfg],
        pattern: &str,
        features: Vec<FindAddrFeature>,
    ) -> Option<Vec<SymbolInfo>> {
        let ctx = Self::find_addr_features_context(features);

        let resolver_map = match ResolverMap::new(sym_srcs, &self.cache_holder) {
            Ok(map) => map,
            _ => {
                return None;
            }
        };
        let mut syms = vec![];
        for (_, resolver) in &resolver_map.resolvers {
            for mut sym in resolver
                .find_address_regex(pattern, &ctx)
                .unwrap_or_default()
            {
                if ctx.offset_in_file {
                    if let Some(off) = resolver.addr_file_off(sym.address) {
                        sym.file_offset = off;
                    }
                }
                if ctx.obj_file_name {
                    sym.obj_file_name = Some(resolver.get_obj_file_name().to_path_buf());
                }
                syms.push(sym);
            }
        }
        Some(syms)
    }

    /// Find the addresses of the symbols matching a pattern.
    ///
    /// Find the addresses of the symbols matching a pattern from the sources
    /// of symbols and debug info described by `sym_srcs`.
    ///
    /// # Arguments
    ///
    /// * `sym_srcs` - A list of symbol and debug sources.
    /// * `pattern` - A regex pattern.
    pub fn find_address_regex(
        &self,
        sym_srcs: &[SymbolSrcCfg],
        pattern: &str,
    ) -> Option<Vec<SymbolInfo>> {
        self.find_address_regex_opt(sym_srcs, pattern, vec![])
    }

    /// Find the addresses of a list of symbol names.
    ///
    /// Find the addresses of a list of symbol names from the sources
    /// of symbols and debug info described by `sym_srcs`.
    /// `find_addresses_opt()` works just like `find_addresses()` with
    /// additional controls on features.
    ///
    /// # Arguments
    ///
    /// * `sym_srcs` - A list of symbol and debug sources.
    /// * `names` - A list of symbol names.
    /// * `features` - a list of `FindAddrFeature` to enable, disable, or specify parameters.
    pub fn find_addresses_opt(
        &self,
        sym_srcs: &[SymbolSrcCfg],
        names: &[&str],
        features: Vec<FindAddrFeature>,
    ) -> Vec<Vec<SymbolInfo>> {
        let ctx = Self::find_addr_features_context(features);

        let resolver_map = match ResolverMap::new(sym_srcs, &self.cache_holder) {
            Ok(map) => map,
            _ => {
                return vec![];
            }
        };
        let mut syms_list = vec![];
        for name in names {
            let mut found = vec![];
            for (_, resolver) in &resolver_map.resolvers {
                if let Some(mut syms) = resolver.find_address(name, &ctx) {
                    for sym in &mut syms {
                        if ctx.offset_in_file {
                            if let Some(off) = resolver.addr_file_off(sym.address) {
                                sym.file_offset = off;
                            }
                        }
                        if ctx.obj_file_name {
                            sym.obj_file_name = Some(resolver.get_obj_file_name().to_path_buf());
                        }
                    }
                    found.append(&mut syms);
                }
            }
            syms_list.push(found);
        }
        syms_list
    }

    /// Find the addresses of a list of symbol names.
    ///
    /// Find the addresses of a list of symbol names from the sources
    /// of symbols and debug info described by `sym_srcs`.
    ///
    /// # Arguments
    ///
    /// * `sym_srcs` - A list of symbol and debug sources.
    /// * `names` - A list of symbol names.
    pub fn find_addresses(
        &self,
        sym_srcs: &[SymbolSrcCfg],
        names: &[&str],
    ) -> Vec<Vec<SymbolInfo>> {
        self.find_addresses_opt(sym_srcs, names, vec![])
    }

    /// Symbolize a list of addresses.
    ///
    /// Symbolize a list of addresses with the information from the
    /// sources of symbols and debug info described by `sym_srcs`.
    ///
    /// # Arguments
    ///
    /// * `sym_srcs` - A list of symbol and debug sources.
    /// * `addresses` - A list of addresses to symbolize.
    pub fn symbolize(
        &self,
        sym_srcs: &[SymbolSrcCfg],
        addresses: &[u64],
    ) -> Vec<Vec<SymbolizedResult>> {
        let resolver_map = if let Ok(map) = ResolverMap::new(sym_srcs, &self.cache_holder) {
            map
        } else {
            #[cfg(debug_assertions)]
            eprintln!("Fail to build ResolverMap");
            return vec![];
        };

        let info: Vec<Vec<SymbolizedResult>> = addresses
            .iter()
            .map(|addr| {
                let resolver = if let Some(resolver) = resolver_map.find_resolver(*addr) {
                    resolver
                } else {
                    return vec![];
                };

                let res_syms = resolver.find_symbols(*addr);
                let linfo = if self.line_number_info {
                    resolver.find_line_info(*addr)
                } else {
                    None
                };
                if res_syms.is_empty() {
                    if let Some(linfo) = linfo {
                        vec![SymbolizedResult {
                            symbol: "".to_string(),
                            start_address: 0,
                            path: linfo.path,
                            line_no: linfo.line_no,
                            column: linfo.column,
                        }]
                    } else {
                        vec![]
                    }
                } else {
                    let mut results = vec![];
                    for sym in res_syms {
                        if let Some(ref linfo) = linfo {
                            let (sym, start) = sym;
                            results.push(SymbolizedResult {
                                symbol: String::from(sym),
                                start_address: start,
                                path: linfo.path.clone(),
                                line_no: linfo.line_no,
                                column: linfo.column,
                            });
                        } else {
                            let (sym, start) = sym;
                            results.push(SymbolizedResult {
                                symbol: String::from(sym),
                                start_address: start,
                                path: "".to_string(),
                                line_no: 0,
                                column: 0,
                            });
                        }
                    }
                    results
                }
            })
            .collect();
        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::Path;

    #[test]
    fn hello_world_stack() {
        // A stack sample from a Hello World proram.
        let stack = vec![
            0xb0, 0xd5, 0xff, 0xff, 0xff, 0x7f, 0x0, 0x0, 0xaf, 0x5, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0,
            0xd0, 0xd5, 0xff, 0xff, 0xff, 0x7f, 0x0, 0x0, 0xcb, 0x5, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        let expected_rips = vec![0x000000000040058a, 0x00000000004005af, 0x00000000004005cb];
        let base = 0x7fffffffd5a0;
        let mut registers: [u64; 17] = [0; 17];

        registers[crate::REG_RIP] = expected_rips[0];
        registers[crate::REG_RBP] = 0x7fffffffd5a0;

        let mut session = crate::X86_64StackSession::new(stack, base, registers);
        let frame = session.next_frame().unwrap();
        assert_eq!(frame.get_ip(), expected_rips[0]);
        let frame = session.next_frame().unwrap();
        assert_eq!(frame.get_ip(), expected_rips[1]);
        let frame = session.next_frame().unwrap();
        assert_eq!(frame.get_ip(), expected_rips[2]);
    }

    #[test]
    fn load_symbolfilecfg_process() {
        // Check if SymbolSrcCfg::Process expands to ELFResolvers.
        let cfg = vec![SymbolSrcCfg::Process { pid: None }];
        let cache_holder = CacheHolder::new(CacheHolderOpts {
            line_number_info: true,
            debug_info_symbols: false,
        });
        let resolver_map = ResolverMap::new(&cfg, &cache_holder);
        assert!(resolver_map.is_ok());
        let resolver_map = resolver_map.unwrap();

        let signatures: Vec<_> = resolver_map.resolvers.iter().map(|x| x.1.repr()).collect();
        // ElfResolver for the binary itself.
        assert!(signatures.iter().any(|x| x.contains("/blazesym")));
        // ElfResolver for libc.
        assert!(signatures.iter().any(|x| x.contains("/libc")));
    }

    #[test]
    fn load_symbolfilecfg_processkernel() {
        // Check if SymbolSrcCfg::Process & SymbolSrcCfg::Kernel expands to
        // ELFResolvers and a KernelResolver.
        let srcs = vec![
            SymbolSrcCfg::Process { pid: None },
            SymbolSrcCfg::Kernel {
                kallsyms: None,
                kernel_image: None,
            },
        ];
        let cache_holder = CacheHolder::new(CacheHolderOpts {
            line_number_info: true,
            debug_info_symbols: false,
        });
        let resolver_map = ResolverMap::new(&srcs, &cache_holder);
        assert!(resolver_map.is_ok());
        let resolver_map = resolver_map.unwrap();

        let signatures: Vec<_> = resolver_map.resolvers.iter().map(|x| x.1.repr()).collect();
        // ElfResolver for the binary itself.
        assert!(signatures.iter().any(|x| x.contains("/blazesym")));
        // ElfResolver for libc.
        assert!(signatures.iter().any(|x| x.contains("/libc")));
        assert!(signatures.iter().any(|x| x.contains("KernelResolver")));
    }

    #[test]
    fn load_symbolfilecfg_invalid_kernel() {
        // Check if SymbolSrcCfg::Kernel expands to a KernelResolver
        // even if kernel_image is invalid.
        let srcs = vec![SymbolSrcCfg::Kernel {
            kallsyms: None,
            kernel_image: Some(PathBuf::from("/dev/null")),
        }];
        let cache_holder = CacheHolder::new(CacheHolderOpts {
            line_number_info: true,
            debug_info_symbols: false,
        });
        let resolver_map = ResolverMap::new(&srcs, &cache_holder);
        assert!(resolver_map.is_ok());
        let resolver_map = resolver_map.unwrap();

        let signatures: Vec<_> = resolver_map.resolvers.iter().map(|x| x.1.repr()).collect();
        assert!(signatures.iter().any(|x| x.contains("KernelResolver")));

        let kallsyms = Path::new("/proc/kallsyms");
        let kernel_image = Path::new("/dev/null");
        let kresolver = KernelResolver::new(kallsyms, kernel_image, &cache_holder).unwrap();
        assert!(kresolver.ksymresolver.is_some());
        assert!(kresolver.kernelresolver.is_none());
    }

    #[test]
    fn load_gsym_resolver() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.gsym");
        let features = vec![SymbolizerFeature::LineNumberInfo(true)];
        let srcs = vec![SymbolSrcCfg::Gsym {
            file_name: test_gsym,
            base_address: 0,
        }];
        let symbolizer = BlazeSymbolizer::new_opt(&features).unwrap();
        let count = symbolizer
            .symbolize(&srcs, &[0x2000100])
            .into_iter()
            .flatten()
            .filter(|result| result.symbol == "factorial")
            .count();
        assert_eq!(count, 1);
    }
}
