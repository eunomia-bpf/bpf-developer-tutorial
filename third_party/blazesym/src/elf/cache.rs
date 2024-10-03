use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::Error;
use std::path::{Path, PathBuf};
use std::ptr;
use std::rc::Rc;

use nix::sys::stat::{fstat, FileStat};
use std::os::unix::io::AsRawFd;

use crate::dwarf::DwarfResolver;

use super::ElfParser;

type ElfCacheEntryKey = PathBuf;

const DFL_CACHE_MAX: usize = 1024;

#[derive(Clone)]
pub enum ElfBackend {
    Dwarf(Rc<DwarfResolver>), // ELF w/ DWARF
    Elf(Rc<ElfParser>),       // ELF w/o DWARF
}

#[cfg(test)]
impl ElfBackend {
    pub fn to_dwarf(&self) -> Option<Rc<DwarfResolver>> {
        if let Self::Dwarf(dwarf) = self {
            Some(Rc::clone(dwarf))
        } else {
            None
        }
    }

    pub fn is_dwarf(&self) -> bool {
        matches!(self, Self::Dwarf(_))
    }
}

struct ElfCacheEntry {
    // LRU links
    prev: *mut ElfCacheEntry,
    next: *mut ElfCacheEntry,

    file_name: PathBuf,

    dev: libc::dev_t,
    inode: libc::ino_t,
    size: libc::off_t,
    mtime_sec: libc::time_t,
    mtime_nsec: i64,
    backend: ElfBackend,
}

impl ElfCacheEntry {
    pub fn new(
        file_name: &Path,
        file: File,
        line_number_info: bool,
        debug_info_symbols: bool,
    ) -> Result<ElfCacheEntry, Error> {
        let stat = fstat(file.as_raw_fd())?;
        let parser = Rc::new(ElfParser::open_file(file)?);
        let backend = if let Ok(dwarf) = DwarfResolver::from_parser_for_addresses(
            Rc::clone(&parser),
            &[],
            line_number_info,
            debug_info_symbols,
        ) {
            ElfBackend::Dwarf(Rc::new(dwarf))
        } else {
            ElfBackend::Elf(parser)
        };

        Ok(ElfCacheEntry {
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
            file_name: file_name.to_path_buf(),
            dev: stat.st_dev,
            inode: stat.st_ino,
            size: stat.st_size,
            mtime_sec: stat.st_mtime,
            mtime_nsec: stat.st_mtime_nsec,
            backend,
        })
    }

    fn get_key(&self) -> &Path {
        &self.file_name
    }

    fn is_valid(&self, stat: &FileStat) -> bool {
        stat.st_dev == self.dev
            && stat.st_ino == self.inode
            && stat.st_size == self.size
            && stat.st_mtime == self.mtime_sec
            && stat.st_mtime_nsec == self.mtime_nsec
    }

    fn get_backend(&self) -> ElfBackend {
        self.backend.clone()
    }
}

/// Maintain a LRU linked list of entries
struct ElfCacheLru {
    head: *mut ElfCacheEntry,
    tail: *mut ElfCacheEntry,
}

impl ElfCacheLru {
    /// # Safety
    ///
    /// Make all entries are valid.
    unsafe fn touch(&mut self, ent: &ElfCacheEntry) {
        unsafe { self.remove(ent) };
        unsafe { self.push_back(ent) };
    }

    /// # Safety
    ///
    /// Make all entries are valid.
    unsafe fn remove(&mut self, ent: &ElfCacheEntry) {
        let ent_ptr = ent as *const ElfCacheEntry as *mut ElfCacheEntry;
        let prev = unsafe { (*ent_ptr).prev };
        let next = unsafe { (*ent_ptr).next };
        if !prev.is_null() {
            unsafe { (*prev).next = next };
        } else {
            self.head = next;
        }
        if !next.is_null() {
            unsafe { (*next).prev = prev };
        } else {
            self.tail = prev;
        }
    }

    /// # Safety
    ///
    /// Make all entries are valid.
    unsafe fn push_back(&mut self, ent: &ElfCacheEntry) {
        let ent_ptr = ent as *const ElfCacheEntry as *mut ElfCacheEntry;
        if self.head.is_null() {
            unsafe { (*ent_ptr).next = ptr::null_mut() };
            unsafe { (*ent_ptr).prev = ptr::null_mut() };
            self.head = ent_ptr;
            self.tail = ent_ptr;
        } else {
            unsafe { (*ent_ptr).next = ptr::null_mut() };
            unsafe { (*self.tail).next = ent_ptr };
            unsafe { (*ent_ptr).prev = self.tail };
            self.tail = ent_ptr;
        }
    }

    /// # Safety
    ///
    /// Make all entries are valid.
    unsafe fn pop_head(&mut self) -> *mut ElfCacheEntry {
        let ent = self.head;
        if !ent.is_null() {
            unsafe { self.remove(&*ent) };
        }
        ent
    }
}

struct _ElfCache {
    elfs: HashMap<ElfCacheEntryKey, Box<ElfCacheEntry>>,
    lru: ElfCacheLru,
    max_elfs: usize,
    line_number_info: bool,
    debug_info_symbols: bool,
}

impl _ElfCache {
    fn new(line_number_info: bool, debug_info_symbols: bool) -> _ElfCache {
        _ElfCache {
            elfs: HashMap::new(),
            lru: ElfCacheLru {
                head: ptr::null_mut(),
                tail: ptr::null_mut(),
            },
            max_elfs: DFL_CACHE_MAX,
            line_number_info,
            debug_info_symbols,
        }
    }

    /// # Safety
    ///
    /// The returned reference is only valid before next time calling
    /// create_entry().
    ///
    unsafe fn find_entry(&mut self, file_name: &Path) -> Option<&ElfCacheEntry> {
        let ent = self.elfs.get(file_name)?;
        unsafe { self.lru.touch(ent) };

        Some(ent.as_ref())
    }

    /// # Safety
    ///
    /// The returned reference is only valid before next time calling
    /// create_entry().
    ///
    unsafe fn create_entry(
        &mut self,
        file_name: &Path,
        file: File,
    ) -> Result<&ElfCacheEntry, Error> {
        let ent = Box::new(ElfCacheEntry::new(
            file_name,
            file,
            self.line_number_info,
            self.debug_info_symbols,
        )?);
        let key = ent.get_key().to_path_buf();

        self.elfs.insert(key.clone(), ent);
        unsafe { self.lru.push_back(self.elfs.get(&key).unwrap().as_ref()) };
        unsafe { self.ensure_size() };

        Ok(unsafe { &*self.lru.tail }) // Get 'static lifetime
    }

    /// # Safety
    ///
    /// This funciton may make some cache entries invalid.  Callers
    /// should be careful about all references of cache entries they
    /// are holding.
    unsafe fn ensure_size(&mut self) {
        if self.elfs.len() > self.max_elfs {
            let to_remove = unsafe { self.lru.pop_head() };
            self.elfs.remove(unsafe { (*to_remove).get_key() }).unwrap();
        }
    }

    fn find_or_create_backend(
        &mut self,
        file_name: &Path,
        file: File,
    ) -> Result<ElfBackend, Error> {
        if let Some(ent) = unsafe { self.find_entry(file_name) } {
            let stat = fstat(file.as_raw_fd())?;

            if ent.is_valid(&stat) {
                return Ok(ent.get_backend());
            }

            // Purge the entry and load it from the filesystem.
            unsafe {
                let ent = &*(ent as *const ElfCacheEntry); // static lifetime to decouple borrowing
                self.lru.remove(ent)
            };
            self.elfs.remove(file_name);
        }

        Ok(unsafe { self.create_entry(file_name, file)? }.get_backend())
    }

    pub fn find(&mut self, path: &Path) -> Result<ElfBackend, Error> {
        let file = File::open(path)?;
        self.find_or_create_backend(path, file)
    }
}

pub struct ElfCache {
    cache: RefCell<_ElfCache>,
}

impl ElfCache {
    pub fn new(line_number_info: bool, debug_info_symbols: bool) -> ElfCache {
        ElfCache {
            cache: RefCell::new(_ElfCache::new(line_number_info, debug_info_symbols)),
        }
    }

    pub fn find(&self, path: &Path) -> Result<ElfBackend, Error> {
        let mut cache = self.cache.borrow_mut();
        cache.find(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_cache() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let cache = ElfCache::new(true, false);
        let backend_first = cache.find(Path::new(&bin_name));
        let backend_second = cache.find(Path::new(&bin_name));
        assert!(backend_first.is_ok());
        assert!(backend_second.is_ok());
        let backend_first = backend_first.unwrap();
        let backend_second = backend_second.unwrap();
        assert!(backend_first.is_dwarf());
        assert!(backend_second.is_dwarf());
        assert_eq!(
            ptr::addr_of!(*backend_first.to_dwarf().unwrap().get_parser()),
            ptr::addr_of!(*backend_second.to_dwarf().unwrap().get_parser())
        );
    }
}
