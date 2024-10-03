use std::alloc::{alloc, dealloc, Layout};
use std::ffi::CStr;
use std::ffi::OsStr;
use std::mem;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::ptr;
use std::u64;

use crate::BlazeSymbolizer;
use crate::FindAddrFeature;
use crate::SymbolInfo;
use crate::SymbolSrcCfg;
use crate::SymbolType;
use crate::SymbolizedResult;
use crate::SymbolizerFeature;


/// Types of symbol sources and debug information for C API.
#[repr(C)]
#[allow(non_camel_case_types, unused)]
pub enum blazesym_src_type {
    /// Symbols and debug information from an ELF file.
    SRC_T_ELF,
    /// Symbols and debug information from a kernel image and its kallsyms.
    SRC_T_KERNEL,
    /// Symbols and debug information from a process, including loaded object files.
    SRC_T_PROCESS,
}

/// The parameters to load symbols and debug information from an ELF.
///
/// Describes the path and address of an ELF file loaded in a
/// process.
#[repr(C)]
pub struct ssc_elf {
    /// The file name of an ELF file.
    ///
    /// It can be an executable or shared object.
    /// For example, passing "/bin/sh" will load symbols and debug information from `sh`.
    /// Whereas passing "/lib/libc.so.xxx" will load symbols and debug information from the libc.
    pub file_name: *const c_char,
    /// The base address is where the file's executable segment(s) is loaded.
    ///
    /// It should be the address
    /// in the process mapping to the executable segment's first byte.
    /// For example, in /proc/&lt;pid&gt;/maps
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
    /// A loader would load an executable segment with the permission of `x`
    /// (executable).  For example, the first block is with the
    /// permission of `r-xp`.
    pub base_address: u64,
}

/// The parameters to load symbols and debug information from a kernel.
///
/// Use a kernel image and a snapshot of its kallsyms as a source of symbols and
/// debug information.
#[repr(C)]
pub struct ssc_kernel {
    /// The path of a copy of kallsyms.
    ///
    /// It can be `"/proc/kallsyms"` for the running kernel on the
    /// device.  However, you can make copies for later.  In that situation,
    /// you should give the path of a copy.
    /// Passing a `NULL`, by default, will result in `"/proc/kallsyms"`.
    pub kallsyms: *const c_char,
    /// The path of a kernel image.
    ///
    /// The path of a kernel image should be, for instance,
    /// `"/boot/vmlinux-xxxx"`.  For a `NULL` value, it will locate the
    /// kernel image of the running kernel in `"/boot/"` or
    /// `"/usr/lib/debug/boot/"`.
    pub kernel_image: *const c_char,
}

/// The parameters to load symbols and debug information from a process.
///
/// Load all ELF files in a process as the sources of symbols and debug
/// information.
#[repr(C)]
pub struct ssc_process {
    /// It is the PID of a process to symbolize.
    ///
    /// BlazeSym will parse `/proc/<pid>/maps` and load all the object
    /// files.
    pub pid: u32,
}

/// Parameters of a symbol source.
#[repr(C)]
pub union ssc_params {
    /// The variant for SRC_T_ELF
    pub elf: mem::ManuallyDrop<ssc_elf>,
    /// The variant for SRC_T_KERNEL
    pub kernel: mem::ManuallyDrop<ssc_kernel>,
    /// The variant for SRC_T_PROCESS
    pub process: mem::ManuallyDrop<ssc_process>,
}

/// Description of a source of symbols and debug information for C API.
#[repr(C)]
pub struct sym_src_cfg {
    /// A type of symbol source.
    pub src_type: blazesym_src_type,
    pub params: ssc_params,
}

/// Names of the BlazeSym features.
#[repr(C)]
#[allow(non_camel_case_types, unused)]
pub enum blazesym_feature_name {
    /// Enable or disable returning line numbers of addresses.
    ///
    /// Users should set `blazesym_feature.params.enable` to enabe or
    /// disable the feature,
    LINE_NUMBER_INFO,
    /// Enable or disable loading symbols from DWARF.
    ///
    /// Users should `blazesym_feature.params.enable` to enable or
    /// disable the feature.  This feature is disabled by default.
    DEBUG_INFO_SYMBOLS,
}

#[repr(C)]
pub union blazesym_feature_params {
    enable: bool,
}

/// Setting of the blazesym features.
///
/// Contain parameters to enable, disable, or customize a feature.
#[repr(C)]
pub struct blazesym_feature {
    pub feature: blazesym_feature_name,
    pub params: blazesym_feature_params,
}

/// A placeholder symbolizer for C API.
///
/// It is returned by [`blazesym_new()`] and should be free by
/// [`blazesym_free()`].
#[repr(C)]
pub struct blazesym {
    symbolizer: *mut BlazeSymbolizer,
}

/// The result of symbolization of an address for C API.
///
/// A `blazesym_csym` is the information of a symbol found for an
/// address.  One address may result in several symbols.
#[repr(C)]
pub struct blazesym_csym {
    /// The symbol name is where the given address should belong to.
    pub symbol: *const c_char,
    /// The address (i.e.,the first byte) is where the symbol is located.
    ///
    /// The address is already relocated to the address space of
    /// the process.
    pub start_address: u64,
    /// The path of the source code defines the symbol.
    pub path: *const c_char,
    /// The instruction of the address is in the line number of the source code.
    pub line_no: usize,
    pub column: usize,
}

/// `blazesym_entry` is the output of symbolization for an address for C API.
///
/// Every address has an `blazesym_entry` in
/// [`blazesym_result::entries`] to collect symbols found by BlazeSym.
#[repr(C)]
pub struct blazesym_entry {
    /// The number of symbols found for an address.
    pub size: usize,
    /// All symbols found.
    ///
    /// `syms` is an array of blazesym_csym in the size `size`.
    pub syms: *const blazesym_csym,
}

/// `blazesym_result` is the result of symbolization for C API.
///
/// The instances of blazesym_result are returned from
/// [`blazesym_symbolize()`].  They should be free by calling
/// [`blazesym_result_free()`].
#[repr(C)]
pub struct blazesym_result {
    /// The number of addresses being symbolized.
    pub size: usize,
    /// The entries for addresses.
    ///
    /// Symbolization occurs based on the order of addresses.
    /// Therefore, every address must have an entry here on the same
    /// order.
    pub entries: [blazesym_entry; 0],
}

/// Create a `PathBuf` from a pointer of C string
///
/// # Safety
///
/// C string should be terminated with a null byte.
///
unsafe fn from_cstr(cstr: *const c_char) -> PathBuf {
    PathBuf::from(unsafe { CStr::from_ptr(cstr) }.to_str().unwrap())
}

unsafe fn symbolsrccfg_to_rust(cfg: *const sym_src_cfg, cfg_len: u32) -> Option<Vec<SymbolSrcCfg>> {
    let mut cfg_rs = Vec::<SymbolSrcCfg>::with_capacity(cfg_len as usize);

    for i in 0..cfg_len {
        let c = unsafe { cfg.offset(i as isize) };
        match unsafe { &(*c).src_type } {
            blazesym_src_type::SRC_T_ELF => {
                cfg_rs.push(SymbolSrcCfg::Elf {
                    file_name: unsafe { from_cstr((*c).params.elf.file_name) },
                    base_address: unsafe { (*c).params.elf.base_address },
                });
            }
            blazesym_src_type::SRC_T_KERNEL => {
                let kallsyms = unsafe { (*c).params.kernel.kallsyms };
                let kernel_image = unsafe { (*c).params.kernel.kernel_image };
                cfg_rs.push(SymbolSrcCfg::Kernel {
                    kallsyms: if !kallsyms.is_null() {
                        Some(unsafe { from_cstr(kallsyms) })
                    } else {
                        None
                    },
                    kernel_image: if !kernel_image.is_null() {
                        Some(unsafe { from_cstr(kernel_image) })
                    } else {
                        None
                    },
                });
            }
            blazesym_src_type::SRC_T_PROCESS => {
                let pid = unsafe { (*c).params.process.pid };
                cfg_rs.push(SymbolSrcCfg::Process {
                    pid: if pid > 0 { Some(pid) } else { None },
                });
            }
        }
    }

    Some(cfg_rs)
}

/// Create an instance of blazesym a symbolizer for C API.
///
/// # Safety
///
/// Free the pointer with [`blazesym_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_new() -> *mut blazesym {
    let symbolizer = match BlazeSymbolizer::new() {
        Ok(s) => s,
        Err(_) => {
            return ptr::null_mut();
        }
    };
    let symbolizer_box = Box::new(symbolizer);
    let c_box = Box::new(blazesym {
        symbolizer: Box::into_raw(symbolizer_box),
    });
    Box::into_raw(c_box)
}

/// Create an instance of blazesym a symbolizer for C API.
///
/// # Safety
///
/// Free the pointer with [`blazesym_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_new_opts(
    features: *const blazesym_feature,
    nfeatures: usize,
) -> *mut blazesym {
    let features_v = unsafe {
        Vec::<blazesym_feature>::from_raw_parts(
            features as *mut blazesym_feature,
            nfeatures,
            nfeatures,
        )
    };
    let features_v = mem::ManuallyDrop::new(features_v);
    let features_r: Vec<_> = features_v
        .iter()
        .map(|x| -> SymbolizerFeature {
            match x.feature {
                blazesym_feature_name::LINE_NUMBER_INFO => {
                    SymbolizerFeature::LineNumberInfo(unsafe { x.params.enable })
                }
                blazesym_feature_name::DEBUG_INFO_SYMBOLS => {
                    SymbolizerFeature::DebugInfoSymbols(unsafe { x.params.enable })
                }
            }
        })
        .collect();

    let symbolizer = match BlazeSymbolizer::new_opt(&features_r) {
        Ok(s) => s,
        Err(_) => {
            return ptr::null_mut();
        }
    };
    let symbolizer_box = Box::new(symbolizer);
    let c_box = Box::new(blazesym {
        symbolizer: Box::into_raw(symbolizer_box),
    });
    Box::into_raw(c_box)
}

/// Free an instance of blazesym a symbolizer for C API.
///
/// # Safety
///
/// The pointer must be returned by [`blazesym_new()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_free(symbolizer: *mut blazesym) {
    if !symbolizer.is_null() {
        drop(unsafe { Box::from_raw((*symbolizer).symbolizer) });
        drop(unsafe { Box::from_raw(symbolizer) });
    }
}

/// Convert SymbolizedResults to blazesym_results.
///
/// # Safety
///
/// The returned pointer should be freed by [`blazesym_result_free()`].
///
unsafe fn convert_symbolizedresults_to_c(
    results: Vec<Vec<SymbolizedResult>>,
) -> *const blazesym_result {
    // Allocate a buffer to contain a blazesym_result, all
    // blazesym_csym, and C strings of symbol and path.
    let strtab_size = results.iter().flatten().fold(0, |acc, result| {
        acc + result.symbol.len() + result.path.len() + 2
    });
    let all_csym_size = results.iter().flatten().count();
    let buf_size = strtab_size
        + mem::size_of::<blazesym_result>()
        + mem::size_of::<blazesym_entry>() * results.len()
        + mem::size_of::<blazesym_csym>() * all_csym_size;
    let raw_buf_with_sz =
        unsafe { alloc(Layout::from_size_align(buf_size + mem::size_of::<u64>(), 8).unwrap()) };
    if raw_buf_with_sz.is_null() {
        return ptr::null();
    }

    // prepend an u64 to keep the size of the buffer.
    unsafe { *(raw_buf_with_sz as *mut u64) = buf_size as u64 };

    let raw_buf = unsafe { raw_buf_with_sz.add(mem::size_of::<u64>()) };

    let result_ptr = raw_buf as *mut blazesym_result;
    let mut entry_last = unsafe { &mut (*result_ptr).entries as *mut blazesym_entry };
    let mut csym_last = unsafe {
        raw_buf.add(
            mem::size_of::<blazesym_result>() + mem::size_of::<blazesym_entry>() * results.len(),
        )
    } as *mut blazesym_csym;
    let mut cstr_last = unsafe {
        raw_buf.add(
            mem::size_of::<blazesym_result>()
                + mem::size_of::<blazesym_entry>() * results.len()
                + mem::size_of::<blazesym_csym>() * all_csym_size,
        )
    } as *mut c_char;

    let mut make_cstr = |src: &str| {
        let cstr = cstr_last;
        unsafe { ptr::copy(src.as_ptr(), cstr as *mut u8, src.len()) };
        unsafe { *cstr.add(src.len()) = 0 };
        cstr_last = unsafe { cstr_last.add(src.len() + 1) };

        cstr
    };

    unsafe { (*result_ptr).size = results.len() };

    // Convert all SymbolizedResults to blazesym_entrys and blazesym_csyms
    for entry in results {
        unsafe { (*entry_last).size = entry.len() };
        unsafe { (*entry_last).syms = csym_last };
        entry_last = unsafe { entry_last.add(1) };

        for r in entry {
            let symbol_ptr = make_cstr(&r.symbol);

            let path_ptr = make_cstr(&r.path);

            let csym_ref = unsafe { &mut *csym_last };
            csym_ref.symbol = symbol_ptr;
            csym_ref.start_address = r.start_address;
            csym_ref.path = path_ptr;
            csym_ref.line_no = r.line_no;
            csym_ref.column = r.column;

            csym_last = unsafe { csym_last.add(1) };
        }
    }

    result_ptr
}

/// Symbolize addresses with the sources of symbols and debug info.
///
/// Return an array of [`blazesym_result`] with the same size as the
/// number of input addresses.  The caller should free the returned
/// array by calling [`blazesym_result_free()`].
///
/// # Safety
///
/// The returned pointer should be freed by [`blazesym_result_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_symbolize(
    symbolizer: *mut blazesym,
    sym_srcs: *const sym_src_cfg,
    sym_srcs_len: u32,
    addrs: *const u64,
    addr_cnt: usize,
) -> *const blazesym_result {
    let sym_srcs_rs =
        if let Some(sym_srcs_rs) = unsafe { symbolsrccfg_to_rust(sym_srcs, sym_srcs_len) } {
            sym_srcs_rs
        } else {
            #[cfg(debug_assertions)]
            eprintln!("Fail to transform configurations of symbolizer from C to Rust");
            return ptr::null_mut();
        };

    let symbolizer = unsafe { &*(*symbolizer).symbolizer };
    let addresses = unsafe { Vec::from_raw_parts(addrs as *mut u64, addr_cnt, addr_cnt) };

    let results = symbolizer.symbolize(&sym_srcs_rs, &addresses);

    addresses.leak();

    if results.is_empty() {
        #[cfg(debug_assertions)]
        eprintln!("Empty result while request for {addr_cnt}");
        return ptr::null();
    }

    unsafe { convert_symbolizedresults_to_c(results) }
}

/// Free an array returned by blazesym_symbolize.
///
/// # Safety
///
/// The pointer must be returned by [`blazesym_symbolize()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_result_free(results: *const blazesym_result) {
    if results.is_null() {
        #[cfg(debug_assertions)]
        eprintln!("blazesym_result_free(null)");
        return;
    }

    let raw_buf_with_sz = unsafe { (results as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize + mem::size_of::<u64>();
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}

#[repr(C)]
pub struct blazesym_sym_info {
    name: *const u8,
    address: u64,
    size: u64,
    sym_type: blazesym_sym_type,
    file_offset: u64,
    obj_file_name: *const u8,
}

/// Convert SymbolInfos returned by BlazeSymbolizer::find_addresses() to a C array.
unsafe fn convert_syms_list_to_c(
    syms_list: Vec<Vec<SymbolInfo>>,
) -> *const *const blazesym_sym_info {
    let mut sym_cnt = 0;
    let mut str_buf_sz = 0;

    for syms in &syms_list {
        sym_cnt += syms.len() + 1;
        for sym in syms {
            str_buf_sz += sym.name.len() + 1;
            if let Some(fname) = sym.obj_file_name.as_ref() {
                str_buf_sz += AsRef::<OsStr>::as_ref(fname).as_bytes().len() + 1;
            }
        }
    }

    let array_sz = ((mem::size_of::<*const u64>() * syms_list.len() + mem::size_of::<u64>() - 1)
        % mem::size_of::<u64>())
        * mem::size_of::<u64>();
    let sym_buf_sz = mem::size_of::<blazesym_sym_info>() * sym_cnt;
    let buf_size = array_sz + sym_buf_sz + str_buf_sz;
    let raw_buf_with_sz =
        unsafe { alloc(Layout::from_size_align(buf_size + mem::size_of::<u64>(), 8).unwrap()) };

    unsafe { *(raw_buf_with_sz as *mut u64) = buf_size as u64 };

    let raw_buf = unsafe { raw_buf_with_sz.add(mem::size_of::<u64>()) };
    let mut syms_ptr = raw_buf as *mut *mut blazesym_sym_info;
    let mut sym_ptr = unsafe { raw_buf.add(array_sz) } as *mut blazesym_sym_info;
    let mut str_ptr = unsafe { raw_buf.add(array_sz + sym_buf_sz) } as *mut u8;

    for syms in syms_list {
        unsafe { *syms_ptr = sym_ptr };
        for SymbolInfo {
            name,
            address,
            size,
            sym_type,
            file_offset,
            obj_file_name,
        } in syms
        {
            let name_ptr = str_ptr as *const u8;
            unsafe { ptr::copy_nonoverlapping(name.as_ptr(), str_ptr, name.len()) };
            str_ptr = unsafe { str_ptr.add(name.len()) };
            unsafe { *str_ptr = 0 };
            str_ptr = unsafe { str_ptr.add(1) };
            let obj_file_name = if let Some(fname) = obj_file_name.as_ref() {
                let fname = AsRef::<OsStr>::as_ref(fname).as_bytes();
                let obj_fname_ptr = str_ptr;
                unsafe { ptr::copy_nonoverlapping(fname.as_ptr(), str_ptr, fname.len()) };
                str_ptr = unsafe { str_ptr.add(fname.len()) };
                unsafe { *str_ptr = 0 };
                str_ptr = unsafe { str_ptr.add(1) };
                obj_fname_ptr
            } else {
                ptr::null()
            };

            unsafe {
                (*sym_ptr) = blazesym_sym_info {
                    name: name_ptr,
                    address,
                    size,
                    sym_type: match sym_type {
                        SymbolType::Function => blazesym_sym_type::SYM_T_FUNC,
                        SymbolType::Variable => blazesym_sym_type::SYM_T_VAR,
                        _ => blazesym_sym_type::SYM_T_UNKNOWN,
                    },
                    file_offset,
                    obj_file_name,
                }
            };
            sym_ptr = unsafe { sym_ptr.add(1) };
        }
        unsafe {
            (*sym_ptr) = blazesym_sym_info {
                name: ptr::null(),
                address: 0,
                size: 0,
                sym_type: blazesym_sym_type::SYM_T_UNKNOWN,
                file_offset: 0,
                obj_file_name: ptr::null(),
            }
        };
        sym_ptr = unsafe { sym_ptr.add(1) };

        syms_ptr = unsafe { syms_ptr.add(1) };
    }

    raw_buf as *const *const blazesym_sym_info
}

/// Convert SymbolInfos returned by BlazeSymbolizer::find_address_regex() to a C array.
unsafe fn convert_syms_to_c(syms: Vec<SymbolInfo>) -> *const blazesym_sym_info {
    let mut str_buf_sz = 0;

    for sym in &syms {
        str_buf_sz += sym.name.len() + 1;
        if let Some(fname) = sym.obj_file_name.as_ref() {
            str_buf_sz += AsRef::<OsStr>::as_ref(fname).as_bytes().len() + 1;
        }
    }

    let sym_buf_sz = mem::size_of::<blazesym_sym_info>() * (syms.len() + 1);
    let buf_size = sym_buf_sz + str_buf_sz;
    let raw_buf_with_sz =
        unsafe { alloc(Layout::from_size_align(buf_size + mem::size_of::<u64>(), 8).unwrap()) };

    unsafe { *(raw_buf_with_sz as *mut u64) = buf_size as u64 };

    let raw_buf = unsafe { raw_buf_with_sz.add(mem::size_of::<u64>()) };
    let mut sym_ptr = raw_buf as *mut blazesym_sym_info;
    let mut str_ptr = unsafe { raw_buf.add(sym_buf_sz) } as *mut u8;

    for sym in syms {
        let SymbolInfo {
            name,
            address,
            size,
            sym_type,
            file_offset,
            obj_file_name,
        } = sym;
        let name_ptr = str_ptr as *const u8;
        unsafe { ptr::copy_nonoverlapping(name.as_ptr(), str_ptr, name.len()) };
        str_ptr = unsafe { str_ptr.add(name.len()) };
        unsafe { *str_ptr = 0 };
        str_ptr = unsafe { str_ptr.add(1) };
        let obj_file_name = if let Some(fname) = obj_file_name.as_ref() {
            let fname = AsRef::<OsStr>::as_ref(fname).as_bytes();
            let obj_fname_ptr = str_ptr;
            unsafe { ptr::copy_nonoverlapping(fname.as_ptr(), str_ptr, fname.len()) };
            str_ptr = unsafe { str_ptr.add(fname.len()) };
            unsafe { *str_ptr = 0 };
            str_ptr = unsafe { str_ptr.add(1) };
            obj_fname_ptr
        } else {
            ptr::null()
        };

        unsafe {
            (*sym_ptr) = blazesym_sym_info {
                name: name_ptr,
                address,
                size,
                sym_type: match sym_type {
                    SymbolType::Function => blazesym_sym_type::SYM_T_FUNC,
                    SymbolType::Variable => blazesym_sym_type::SYM_T_VAR,
                    _ => blazesym_sym_type::SYM_T_UNKNOWN,
                },
                file_offset,
                obj_file_name,
            }
        };
        sym_ptr = unsafe { sym_ptr.add(1) };
    }
    unsafe {
        (*sym_ptr) = blazesym_sym_info {
            name: ptr::null(),
            address: 0,
            size: 0,
            sym_type: blazesym_sym_type::SYM_T_UNKNOWN,
            file_offset: 0,
            obj_file_name: ptr::null(),
        }
    };

    raw_buf as *const blazesym_sym_info
}

/// The types of symbols.
///
/// This type is used to choice what type of symbols you like to find
/// and indicate the types of symbols found.
#[repr(C)]
#[allow(non_camel_case_types, unused)]
#[derive(Copy, Clone)]
pub enum blazesym_sym_type {
    /// Invalid type
    SYM_T_INVALID,
    /// You want to find a symbol of any type.
    SYM_T_UNKNOWN,
    /// The returned symbol is a function, or you want to find a function.
    SYM_T_FUNC,
    /// The returned symbol is a variable, or you want to find a variable.
    SYM_T_VAR,
}

/// Feature names of looking up addresses of symbols.
#[repr(C)]
#[allow(non_camel_case_types, unused)]
pub enum blazesym_faf_type {
    /// Invalid type
    FAF_T_INVALID,
    /// Return the offset in the file. (enable)
    FAF_T_OFFSET_IN_FILE,
    /// Return the file name of the shared object. (enable)
    FAF_T_OBJ_FILE_NAME,
    /// Return symbols having the given type. (sym_type)
    FAF_T_SYMBOL_TYPE,
}

/// The parameter parts of `blazesym_faddr_feature`.
#[repr(C)]
pub union blazesym_faf_param {
    enable: bool,
    sym_type: blazesym_sym_type,
}

/// Switches and settings of features of looking up addresses of
/// symbols.
///
/// See [`FindAddrFeature`] for details.
#[repr(C)]
pub struct blazesym_faddr_feature {
    ftype: blazesym_faf_type,
    param: blazesym_faf_param,
}

unsafe fn convert_find_addr_features(
    features: *const blazesym_faddr_feature,
    num_features: usize,
) -> Vec<FindAddrFeature> {
    let mut feature = features;
    let mut features_ret = vec![];
    for _ in 0..num_features {
        match unsafe { &(*feature).ftype } {
            blazesym_faf_type::FAF_T_SYMBOL_TYPE => {
                features_ret.push(match unsafe { (*feature).param.sym_type } {
                    blazesym_sym_type::SYM_T_UNKNOWN => {
                        FindAddrFeature::SymbolType(SymbolType::Unknown)
                    }
                    blazesym_sym_type::SYM_T_FUNC => {
                        FindAddrFeature::SymbolType(SymbolType::Function)
                    }
                    blazesym_sym_type::SYM_T_VAR => {
                        FindAddrFeature::SymbolType(SymbolType::Variable)
                    }
                    _ => {
                        panic!("Invalid symbol type");
                    }
                });
            }
            blazesym_faf_type::FAF_T_OFFSET_IN_FILE => {
                features_ret.push(FindAddrFeature::OffsetInFile(unsafe {
                    (*feature).param.enable
                }));
            }
            blazesym_faf_type::FAF_T_OBJ_FILE_NAME => {
                features_ret.push(FindAddrFeature::ObjFileName(unsafe {
                    (*feature).param.enable
                }));
            }
            _ => {
                panic!("Unknown find_address feature type");
            }
        }
        feature = unsafe { feature.add(1) };
    }

    features_ret
}

/// Find the addresses of symbols matching a pattern.
///
/// Return an array of `blazesym_sym_info` ending with an item having a null address.
/// input names.  The caller should free the returned array by calling
/// [`blazesym_syms_free()`].
///
/// It works the same as [`blazesym_find_address_regex()`] with
/// additional controls on features.
///
/// # Safety
///
/// The returned pointer should be free by [`blazesym_syms_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_find_address_regex_opt(
    symbolizer: *mut blazesym,
    sym_srcs: *const sym_src_cfg,
    sym_srcs_len: u32,
    pattern: *const c_char,
    features: *const blazesym_faddr_feature,
    num_features: usize,
) -> *const blazesym_sym_info {
    let sym_srcs_rs =
        if let Some(sym_srcs_rs) = unsafe { symbolsrccfg_to_rust(sym_srcs, sym_srcs_len) } {
            sym_srcs_rs
        } else {
            #[cfg(debug_assertions)]
            eprintln!("Fail to transform configurations of symbolizer from C to Rust");
            return ptr::null_mut();
        };

    let symbolizer = unsafe { &*(*symbolizer).symbolizer };

    let pattern = unsafe { CStr::from_ptr(pattern) };
    let features = unsafe { convert_find_addr_features(features, num_features) };
    let syms =
        { symbolizer.find_address_regex_opt(&sym_srcs_rs, pattern.to_str().unwrap(), features) };

    if syms.is_none() {
        return ptr::null_mut();
    }

    unsafe { convert_syms_to_c(syms.unwrap()) }
}

/// Find the addresses of symbols matching a pattern.
///
/// Return an array of `blazesym_sym_info` ending with an item having a null address.
/// input names.  The caller should free the returned array by calling
/// [`blazesym_syms_free()`].
///
/// # Safety
///
/// The returned pointer should be free by [`blazesym_syms_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_find_address_regex(
    symbolizer: *mut blazesym,
    sym_srcs: *const sym_src_cfg,
    sym_srcs_len: u32,
    pattern: *const c_char,
) -> *const blazesym_sym_info {
    unsafe {
        blazesym_find_address_regex_opt(symbolizer, sym_srcs, sym_srcs_len, pattern, ptr::null(), 0)
    }
}

/// Free an array returned by blazesym_find_addr_regex() or
/// blazesym_find_addr_regex_opt().
///
/// # Safety
///
/// The `syms` pointer should have been allocated by one of the
/// `blazesym_find_address*` variants.
#[no_mangle]
pub unsafe extern "C" fn blazesym_syms_free(syms: *const blazesym_sym_info) {
    if syms.is_null() {
        #[cfg(debug_assertions)]
        eprintln!("blazesym_sym_info_free(null)");
        return;
    }

    let raw_buf_with_sz = unsafe { (syms as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize + mem::size_of::<u64>();
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}

/// Find the addresses of a list of symbols.
///
/// Return an array of `*const u64` with the same size as the
/// input names.  The caller should free the returned array by calling
/// [`blazesym_syms_list_free()`].
///
/// Every name in the input name list may have more than one address.
/// The respective entry in the returned array is an array containing
/// all addresses and ended with a null (0x0).
///
/// # Safety
///
/// The returned pointer should be free by [`blazesym_syms_list_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_find_addresses_opt(
    symbolizer: *mut blazesym,
    sym_srcs: *const sym_src_cfg,
    sym_srcs_len: u32,
    names: *const *const c_char,
    name_cnt: usize,
    features: *const blazesym_faddr_feature,
    num_features: usize,
) -> *const *const blazesym_sym_info {
    let sym_srcs_rs =
        if let Some(sym_srcs_rs) = unsafe { symbolsrccfg_to_rust(sym_srcs, sym_srcs_len) } {
            sym_srcs_rs
        } else {
            #[cfg(debug_assertions)]
            eprintln!("Fail to transform configurations of symbolizer from C to Rust");
            return ptr::null_mut();
        };

    let symbolizer = unsafe { &*(*symbolizer).symbolizer };

    let mut names_cstr = vec![];
    for i in 0..name_cnt {
        let name_c = unsafe { *names.add(i) };
        let name_r = unsafe { CStr::from_ptr(name_c) };
        names_cstr.push(name_r);
    }
    let features = unsafe { convert_find_addr_features(features, num_features) };
    let syms = {
        let mut names_r = vec![];
        for name in names_cstr.iter().take(name_cnt) {
            names_r.push(name.to_str().unwrap());
        }
        symbolizer.find_addresses_opt(&sym_srcs_rs, &names_r, features)
    };

    unsafe { convert_syms_list_to_c(syms) }
}

/// Find addresses of a symbol name.
///
/// A symbol may have multiple addressses.
///
/// # Safety
///
/// The returned data should be free by [`blazesym_syms_list_free()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_find_addresses(
    symbolizer: *mut blazesym,
    sym_srcs: *const sym_src_cfg,
    sym_srcs_len: u32,
    names: *const *const c_char,
    name_cnt: usize,
) -> *const *const blazesym_sym_info {
    unsafe {
        blazesym_find_addresses_opt(
            symbolizer,
            sym_srcs,
            sym_srcs_len,
            names,
            name_cnt,
            ptr::null(),
            0,
        )
    }
}

/// Free an array returned by blazesym_find_addresses.
///
/// # Safety
///
/// The pointer must be returned by [`blazesym_find_addresses()`].
///
#[no_mangle]
pub unsafe extern "C" fn blazesym_syms_list_free(syms_list: *const *const blazesym_sym_info) {
    if syms_list.is_null() {
        #[cfg(debug_assertions)]
        eprintln!("blazesym_syms_list_free(null)");
        return;
    }

    let raw_buf_with_sz =
        unsafe { (syms_list as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize + mem::size_of::<u64>();
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}
