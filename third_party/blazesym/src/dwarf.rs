use super::elf::ElfParser;
use super::util::{
    decode_leb128, decode_leb128_s, decode_udword, decode_uhalf, decode_uword, search_address_key,
};
use super::{FindAddrOpts, SymbolInfo, SymbolType};
use crossbeam_channel::unbounded;

use std::cell::RefCell;
use std::io::{Error, ErrorKind};
use std::iter::Iterator;
use std::mem;
#[cfg(test)]
use std::path::Path;
use std::rc::Rc;

#[cfg(test)]
use std::env;

use std::clone::Clone;
use std::ffi::CStr;
use std::sync::mpsc;
use std::thread;

use regex::Regex;

#[allow(non_upper_case_globals, unused)]
mod constants;
#[allow(non_upper_case_globals)]
mod debug_info;

#[repr(C, packed)]
struct DebugLinePrologueV2 {
    total_length: u32,
    version: u16,
    prologue_length: u32,
    minimum_instruction_length: u8,
    default_is_stmt: u8,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
}

/// DebugLinePrologue is actually a V4.
///
/// DebugLinePrologueV2 will be converted to this type.
#[repr(C, packed)]
struct DebugLinePrologue {
    total_length: u32,
    version: u16,
    prologue_length: u32,
    minimum_instruction_length: u8,
    maximum_ops_per_instruction: u8,
    default_is_stmt: u8,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
}

/// The file information of a file for a CU.
struct DebugLineFileInfo {
    name: String,
    dir_idx: u32, // Index to include_directories of DebugLineCU.
    _mod_tm: u64,
    _size: usize,
}

/// Represent a Compile Unit (CU) in a .debug_line section.
struct DebugLineCU {
    prologue: DebugLinePrologue,
    _standard_opcode_lengths: Vec<u8>,
    include_directories: Vec<String>,
    files: Vec<DebugLineFileInfo>,
    matrix: Vec<DebugLineStates>,
}

impl DebugLineCU {
    fn find_line(&self, address: u64) -> Option<(&str, &str, usize)> {
        let idx = search_address_key(&self.matrix, address, &|x: &DebugLineStates| -> u64 {
            x.address
        })?;

        let states = &self.matrix[idx];
        if states.end_sequence {
            // This is the first byte after the last instruction
            return None;
        }

        self.stringify_row(idx)
    }

    fn stringify_row(&self, idx: usize) -> Option<(&str, &str, usize)> {
        let states = &self.matrix[idx];
        let (dir, file) = {
            if states.file > 0 {
                let file = &self.files[states.file - 1];
                let dir = {
                    if file.dir_idx == 0 {
                        ""
                    } else {
                        self.include_directories[file.dir_idx as usize - 1].as_str()
                    }
                };
                (dir, file.name.as_str())
            } else {
                ("", "")
            }
        };

        Some((dir, file, states.line))
    }
}

/// Parse the list of directory paths for a CU.
fn parse_debug_line_dirs(data_buf: &[u8]) -> Result<(Vec<String>, usize), Error> {
    let mut strs = Vec::<String>::new();
    let mut pos = 0;

    while pos < data_buf.len() {
        if data_buf[pos] == 0 {
            return Ok((strs, pos + 1));
        }

        // Find NUL byte
        let mut end = pos;
        while end < data_buf.len() && data_buf[end] != 0 {
            end += 1;
        }
        if end < data_buf.len() {
            let mut str_vec = Vec::<u8>::with_capacity(end - pos);
            str_vec.extend_from_slice(&data_buf[pos..end]);

            let str_r = String::from_utf8(str_vec)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid UTF-8 string"))?;
            strs.push(str_r);
            end += 1;
        }
        pos = end;
    }

    Err(Error::new(
        ErrorKind::InvalidData,
        "Did not find NULL terminated string",
    ))
}

/// Parse the list of file information for a CU.
fn parse_debug_line_files(data_buf: &[u8]) -> Result<(Vec<DebugLineFileInfo>, usize), Error> {
    let mut strs = Vec::<DebugLineFileInfo>::new();
    let mut pos = 0;

    while pos < data_buf.len() {
        if data_buf[pos] == 0 {
            return Ok((strs, pos + 1));
        }

        // Find NULL byte
        let mut end = pos;
        while end < data_buf.len() && data_buf[end] != 0 {
            end += 1;
        }
        if end < data_buf.len() {
            // Null terminated file name string
            let mut str_vec = Vec::<u8>::with_capacity(end - pos);
            str_vec.extend_from_slice(&data_buf[pos..end]);

            let str_r = String::from_utf8(str_vec);
            if str_r.is_err() {
                return Err(Error::new(ErrorKind::InvalidData, "Invalid UTF-8 string"));
            }
            end += 1;

            // LEB128 directory index
            let dir_idx_r = decode_leb128(&data_buf[end..]);
            if dir_idx_r.is_none() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid directory index",
                ));
            }
            let (dir_idx, bytes) = dir_idx_r.unwrap();
            end += bytes as usize;

            // LEB128 last modified time
            let mod_tm_r = decode_leb128(&data_buf[end..]);
            if mod_tm_r.is_none() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid last modified time",
                ));
            }
            let (mod_tm, bytes) = mod_tm_r.unwrap();
            end += bytes as usize;

            // LEB128 file size
            let flen_r = decode_leb128(&data_buf[end..]);
            if flen_r.is_none() {
                return Err(Error::new(ErrorKind::InvalidData, "Invalid file size"));
            }
            let (flen, bytes) = flen_r.unwrap();
            end += bytes as usize;

            strs.push(DebugLineFileInfo {
                name: str_r.unwrap(),
                dir_idx: dir_idx as u32,
                _mod_tm: mod_tm,
                _size: flen as usize,
            });
        }
        pos = end;
    }

    Err(Error::new(
        ErrorKind::InvalidData,
        "Do not found null string",
    ))
}

fn parse_debug_line_cu(
    parser: &ElfParser,
    addresses: &[u64],
    reused_buf: &mut Vec<u8>,
) -> Result<DebugLineCU, Error> {
    let mut prologue_sz: usize = mem::size_of::<DebugLinePrologueV2>();
    let prologue_v4_sz: usize = mem::size_of::<DebugLinePrologue>();
    let buf = reused_buf;

    buf.resize(prologue_sz, 0);
    unsafe { parser.read_raw(buf.as_mut_slice()) }?;
    let prologue_raw = buf.as_mut_ptr() as *mut DebugLinePrologueV2;
    // SAFETY: `prologue_raw` is valid for reads and `DebugLinePrologueV2` is
    //         comprised only of objects that are valid for any bit pattern.
    let v2 = unsafe { prologue_raw.read_unaligned() };

    if v2.version != 0x2 && v2.version != 0x4 {
        let version = v2.version;
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!("Support DWARF version 2 & 4 (version: {version})"),
        ));
    }

    let prologue = if v2.version == 0x4 {
        // Upgrade to V4.
        // V4 has more fields to read.
        buf.resize(prologue_v4_sz, 0);
        unsafe { parser.read_raw(&mut buf.as_mut_slice()[prologue_sz..]) }?;
        let prologue_raw = buf.as_mut_ptr() as *mut DebugLinePrologue;
        // SAFETY: `prologue_raw` is valid for reads and `DebugLinePrologue` is
        //         comprised only of objects that are valid for any bit pattern.
        let prologue_v4 = unsafe { prologue_raw.read_unaligned() };
        prologue_sz = prologue_v4_sz;
        prologue_v4
    } else {
        // Convert V2 to V4
        let prologue_v4 = DebugLinePrologue {
            total_length: v2.total_length,
            version: v2.version,
            prologue_length: v2.prologue_length,
            minimum_instruction_length: v2.minimum_instruction_length,
            maximum_ops_per_instruction: 0,
            default_is_stmt: v2.default_is_stmt,
            line_base: v2.line_base,
            line_range: v2.line_range,
            opcode_base: v2.opcode_base,
        };
        prologue_v4
    };

    let to_read = prologue.total_length as usize + 4 - prologue_sz;
    let data_buf = buf;
    if to_read <= data_buf.capacity() {
        // Gain better performance by skipping initialization.
        unsafe { data_buf.set_len(to_read) };
    } else {
        data_buf.resize(to_read, 0);
    }
    unsafe { parser.read_raw(data_buf.as_mut_slice())? };

    let mut pos = 0;

    let std_op_num = (prologue.opcode_base - 1) as usize;
    let mut std_op_lengths = Vec::<u8>::with_capacity(std_op_num);
    std_op_lengths.extend_from_slice(&data_buf[pos..pos + std_op_num]);
    pos += std_op_num;

    let (inc_dirs, bytes) = parse_debug_line_dirs(&data_buf[pos..])?;
    pos += bytes;

    let (files, bytes) = parse_debug_line_files(&data_buf[pos..])?;
    pos += bytes;

    let matrix = run_debug_line_stmts(&data_buf[pos..], &prologue, addresses)?;

    #[cfg(debug_assertions)]
    for i in 1..matrix.len() {
        if matrix[i].address < matrix[i - 1].address && !matrix[i - 1].end_sequence {
            panic!(
                "Not in ascending order @ [{}] {:?} [{}] {:?}",
                i - 1,
                matrix[i - 1],
                i,
                matrix[i]
            );
        }
    }

    Ok(DebugLineCU {
        prologue,
        _standard_opcode_lengths: std_op_lengths,
        include_directories: inc_dirs,
        files,
        matrix,
    })
}

#[derive(Clone, Debug)]
struct DebugLineStates {
    address: u64,
    file: usize,
    line: usize,
    column: usize,
    discriminator: u64,
    is_stmt: bool,
    basic_block: bool,
    end_sequence: bool,
    prologue_end: bool,
    should_reset: bool,
}

impl DebugLineStates {
    fn new(prologue: &DebugLinePrologue) -> DebugLineStates {
        DebugLineStates {
            address: 0,
            file: 1,
            line: 1,
            column: 0,
            discriminator: 0,
            is_stmt: prologue.default_is_stmt != 0,
            basic_block: false,
            end_sequence: false,
            prologue_end: false,
            should_reset: false,
        }
    }

    fn reset(&mut self, prologue: &DebugLinePrologue) {
        self.address = 0;
        self.file = 1;
        self.line = 1;
        self.column = 0;
        self.discriminator = 0;
        self.is_stmt = prologue.default_is_stmt != 0;
        self.basic_block = false;
        self.end_sequence = false;
        self.prologue_end = false;
        self.should_reset = false;
    }
}

/// Return `Ok((insn_bytes, emit))` if success.  `insn_bytes1 is the
/// size of the instruction at the position given by ip.  `emit` is
/// true if this instruction emit a new row to describe line
/// information of an address.  Not every instructions emit rows.
/// Some instructions create only intermediate states for the next row
/// going to emit.
fn run_debug_line_stmt(
    stmts: &[u8],
    prologue: &DebugLinePrologue,
    ip: usize,
    states: &mut DebugLineStates,
) -> Result<(usize, bool), Error> {
    // Standard opcodes
    const DW_LNS_EXT: u8 = 0;
    const DW_LNS_COPY: u8 = 1;
    const DW_LNS_ADVANCE_PC: u8 = 2;
    const DW_LNS_ADVANCE_LINE: u8 = 3;
    const DW_LNS_SET_FILE: u8 = 4;
    const DW_LNS_SET_COLUMN: u8 = 5;
    const DW_LNS_NEGATE_STMT: u8 = 6;
    const DW_LNS_SET_BASIC_BLOCK: u8 = 7;
    const DW_LNS_CONST_ADD_PC: u8 = 8;
    const DW_LNS_FIXED_ADVANCE_PC: u8 = 9;
    const DW_LNS_SET_PROLOGUE_END: u8 = 10;

    // Extended opcodes
    const DW_LINE_END_SEQUENCE: u8 = 1;
    const DW_LINE_SET_ADDRESS: u8 = 2;
    const DW_LINE_DEFINE_FILE: u8 = 3;
    const DW_LINE_SET_DISCRIMINATOR: u8 = 4;

    let opcode_base = prologue.opcode_base;
    let opcode = stmts[ip];

    match opcode {
        DW_LNS_EXT => {
            // Extended opcodes
            if let Some((insn_size, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                if insn_size < 1 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("invalid extended opcode (ip=0x{ip:x}, insn_size=0x{insn_size:x}"),
                    ));
                }
                let ext_opcode = stmts[ip + 1 + bytes as usize];
                match ext_opcode {
                    DW_LINE_END_SEQUENCE => {
                        states.end_sequence = true;
                        states.should_reset = true;
                        Ok((1 + bytes as usize + insn_size as usize, true))
                    }
                    DW_LINE_SET_ADDRESS => match insn_size - 1 {
                        4 => {
                            let address = decode_uword(&stmts[(ip + 1 + bytes as usize + 1)..]);
                            states.address = address as u64;
                            Ok((1 + bytes as usize + insn_size as usize, false))
                        }
                        8 => {
                            let address = decode_udword(&stmts[(ip + 1 + bytes as usize + 1)..]);
                            states.address = address;
                            Ok((1 + bytes as usize + insn_size as usize, false))
                        }
                        _ => Err(Error::new(
                            ErrorKind::Unsupported,
                            format!("unsupported address size ({insn_size})"),
                        )),
                    },
                    DW_LINE_DEFINE_FILE => Err(Error::new(
                        ErrorKind::Unsupported,
                        "DW_LINE_define_file is not supported yet",
                    )),
                    DW_LINE_SET_DISCRIMINATOR => {
                        if let Some((discriminator, discr_bytes)) =
                            decode_leb128(&stmts[(ip + 1 + bytes as usize + 1)..])
                        {
                            if discr_bytes as u64 + 1 == insn_size {
                                states.discriminator = discriminator;
                                Ok((1 + bytes as usize + insn_size as usize, false))
                            } else {
                                Err(Error::new(
                                    ErrorKind::InvalidData,
                                    "unmatched instruction size for DW_LINE_set_discriminator",
                                ))
                            }
                        } else {
                            Err(Error::new(
                                ErrorKind::InvalidData,
                                "discriminator is broken",
                            ))
                        }
                    }
                    _ => Err(Error::new(
                        ErrorKind::Unsupported,
                        format!(
                            "invalid extended opcode (ip=0x{ip:x}, ext_opcode=0x{ext_opcode:x})"
                        ),
                    )),
                }
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid extended opcode (ip=0x{ip:x})"),
                ))
            }
        }
        DW_LNS_COPY => Ok((1, true)),
        DW_LNS_ADVANCE_PC => {
            if let Some((adv, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                states.address += adv * prologue.minimum_instruction_length as u64;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of advance_pc is broken",
                ))
            }
        }
        DW_LNS_ADVANCE_LINE => {
            if let Some((adv, bytes)) = decode_leb128_s(&stmts[(ip + 1)..]) {
                states.line = (states.line as i64 + adv) as usize;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of advance_line is broken",
                ))
            }
        }
        DW_LNS_SET_FILE => {
            if let Some((file_idx, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                states.file = file_idx as usize;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of set_file is broken",
                ))
            }
        }
        DW_LNS_SET_COLUMN => {
            if let Some((column, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                states.column = column as usize;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of set_column is broken",
                ))
            }
        }
        DW_LNS_NEGATE_STMT => {
            states.is_stmt = !states.is_stmt;
            Ok((1, false))
        }
        DW_LNS_SET_BASIC_BLOCK => {
            states.basic_block = true;
            Ok((1, false))
        }
        DW_LNS_CONST_ADD_PC => {
            let addr_adv = (255 - opcode_base) / prologue.line_range;
            states.address += addr_adv as u64 * prologue.minimum_instruction_length as u64;
            Ok((1, false))
        }
        DW_LNS_FIXED_ADVANCE_PC => {
            if (ip + 3) < stmts.len() {
                let addr_adv = decode_uhalf(&stmts[(ip + 1)..]);
                states.address += addr_adv as u64 * prologue.minimum_instruction_length as u64;
                Ok((1, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of fixed_advance_pc is broken",
                ))
            }
        }
        DW_LNS_SET_PROLOGUE_END => {
            states.prologue_end = true;
            Ok((1, false))
        }
        _ => {
            // Special opcodes
            let desired_line_incr = (opcode - opcode_base) % prologue.line_range;
            let addr_adv = (opcode - opcode_base) / prologue.line_range;
            states.address += addr_adv as u64 * prologue.minimum_instruction_length as u64;
            states.line = (states.line as i64
                + (desired_line_incr as i16 + prologue.line_base as i16) as i64
                    * prologue.minimum_instruction_length as i64)
                as usize;
            Ok((1, true))
        }
    }
}

fn run_debug_line_stmts(
    stmts: &[u8],
    prologue: &DebugLinePrologue,
    addresses: &[u64],
) -> Result<Vec<DebugLineStates>, Error> {
    let mut ip = 0;
    let mut matrix = Vec::<DebugLineStates>::new();
    let mut should_sort = false;
    let mut states_cur = DebugLineStates::new(prologue);
    let mut states_last = states_cur.clone();
    let mut last_ip_pushed = false;
    let mut force_no_emit = false;

    while ip < stmts.len() {
        match run_debug_line_stmt(stmts, prologue, ip, &mut states_cur) {
            Ok((sz, emit)) => {
                ip += sz;
                if emit {
                    if states_cur.address == 0 {
                        // This is a special case. Somehow, rust
                        // compiler generate debug_line for some
                        // builtin code starting from 0.  And, it
                        // causes incorrect behavior.
                        force_no_emit = true;
                    }
                    if !force_no_emit {
                        if !addresses.is_empty() {
                            let mut pushed = false;
                            for addr in addresses {
                                if *addr == states_cur.address
                                    || (states_last.address != 0
                                        && !states_last.end_sequence
                                        && *addr < states_cur.address
                                        && *addr > states_last.address)
                                {
                                    if !last_ip_pushed && *addr != states_cur.address {
                                        // The address falls between current and last emitted row.
                                        matrix.push(states_last.clone());
                                    }
                                    matrix.push(states_cur.clone());
                                    pushed = true;
                                    break;
                                }
                            }
                            last_ip_pushed = pushed;
                            states_last = states_cur.clone();
                        } else {
                            matrix.push(states_cur.clone());
                        }
                        if states_last.address > states_cur.address {
                            should_sort = true;
                        }
                    }
                }
                if states_cur.should_reset {
                    states_cur.reset(prologue);
                    force_no_emit = false;
                }
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    if should_sort {
        matrix.sort_by_key(|x| x.address);
    }

    Ok(matrix)
}

/// If addresses is empty, it returns a full version of debug_line matrix.
/// If addresses is not empty, return only data needed to resolve given addresses .
fn parse_debug_line_elf_parser(
    parser: &ElfParser,
    addresses: &[u64],
) -> Result<Vec<DebugLineCU>, Error> {
    let debug_line_idx = parser.find_section(".debug_line")?;
    let debug_line_sz = parser.get_section_size(debug_line_idx)?;
    let mut remain_sz = debug_line_sz;
    let prologue_size: usize = mem::size_of::<DebugLinePrologueV2>();
    let mut not_found = Vec::from(addresses);

    parser.section_seek(debug_line_idx)?;

    let mut all_cus = Vec::<DebugLineCU>::new();
    let mut buf = Vec::<u8>::new();
    while remain_sz > prologue_size {
        let debug_line_cu = parse_debug_line_cu(parser, &not_found, &mut buf)?;
        let prologue = &debug_line_cu.prologue;
        remain_sz -= prologue.total_length as usize + 4;

        if debug_line_cu.matrix.is_empty() {
            continue;
        }

        if !addresses.is_empty() {
            let mut last_row = &debug_line_cu.matrix[0];
            for row in debug_line_cu.matrix.as_slice() {
                let mut i = 0;
                // Remove addresses found in this CU from not_found.
                while i < not_found.len() {
                    let addr = addresses[i];
                    if addr == row.address || (addr < row.address && addr > last_row.address) {
                        not_found.remove(i);
                    } else {
                        i += 1;
                    }
                }
                last_row = row;
            }

            all_cus.push(debug_line_cu);

            if not_found.is_empty() {
                return Ok(all_cus);
            }
        } else {
            all_cus.push(debug_line_cu);
        }
    }

    if remain_sz != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "encountered remaining garbage data at the end",
        ));
    }

    Ok(all_cus)
}

/// DwarfResolver provides abilities to query DWARF information of binaries.
pub struct DwarfResolver {
    parser: Rc<ElfParser>,
    debug_line_cus: Vec<DebugLineCU>,
    addr_to_dlcu: Vec<(u64, u32)>,
    enable_debug_info_syms: bool,
    debug_info_syms: RefCell<Option<Vec<DWSymInfo<'static>>>>,
}

impl DwarfResolver {
    pub fn get_parser(&self) -> &ElfParser {
        &self.parser
    }

    pub fn from_parser_for_addresses(
        parser: Rc<ElfParser>,
        addresses: &[u64],
        line_number_info: bool,
        debug_info_symbols: bool,
    ) -> Result<DwarfResolver, Error> {
        let debug_line_cus: Vec<DebugLineCU> = if line_number_info {
            parse_debug_line_elf_parser(&parser, addresses).unwrap_or_default()
        } else {
            vec![]
        };

        let mut addr_to_dlcu = Vec::with_capacity(debug_line_cus.len());
        for (idx, dlcu) in debug_line_cus.iter().enumerate() {
            if dlcu.matrix.is_empty() {
                continue;
            }
            let first_addr = dlcu.matrix[0].address;
            addr_to_dlcu.push((first_addr, idx as u32));
        }
        addr_to_dlcu.sort_by_key(|v| v.0);

        Ok(DwarfResolver {
            parser,
            debug_line_cus,
            addr_to_dlcu,
            enable_debug_info_syms: debug_info_symbols,
            debug_info_syms: RefCell::new(None),
        })
    }

    /// Open a binary to load .debug_line only enough for a given list of addresses.
    ///
    /// When `addresses` is not empty, the returned instance only has
    /// data that related to these addresses.  For this case, the
    /// isntance have the ability that can serve only these addresses.
    /// This would be much faster.
    ///
    /// If `addresses` is empty, the returned instance has all data
    /// from the given file.  If the instance will be used for long
    /// running, you would want to load all data into memory to have
    /// the ability of handling all possible addresses.
    #[cfg(test)]
    fn open_for_addresses(
        filename: &Path,
        addresses: &[u64],
        line_number_info: bool,
        debug_info_symbols: bool,
    ) -> Result<DwarfResolver, Error> {
        let parser = ElfParser::open(filename)?;
        Self::from_parser_for_addresses(
            Rc::new(parser),
            addresses,
            line_number_info,
            debug_info_symbols,
        )
    }

    /// Open a binary to load and parse .debug_line for later uses.
    ///
    /// `filename` is the name of an ELF binary/or shared object that
    /// has .debug_line section.
    #[cfg(test)]
    pub fn open(
        filename: &Path,
        debug_line_info: bool,
        debug_info_symbols: bool,
    ) -> Result<DwarfResolver, Error> {
        Self::open_for_addresses(filename, &[], debug_line_info, debug_info_symbols)
    }

    fn find_dlcu_index(&self, address: u64) -> Option<usize> {
        let a2a = &self.addr_to_dlcu;
        let a2a_idx = search_address_key(a2a, address, &|x: &(u64, u32)| -> u64 { x.0 })?;
        let dlcu_idx = a2a[a2a_idx].1 as usize;

        Some(dlcu_idx)
    }

    /// Find line information of an address.
    ///
    /// `address` is an offset from the head of the loaded binary/or
    /// shared object.  This function returns a tuple of `(dir_name, file_name, line_no)`.
    pub fn find_line_as_ref(&self, address: u64) -> Option<(&str, &str, usize)> {
        let idx = self.find_dlcu_index(address)?;
        let dlcu = &self.debug_line_cus[idx];

        dlcu.find_line(address)
    }

    /// Find line information of an address.
    ///
    /// `address` is an offset from the head of the loaded binary/or
    /// shared object.  This function returns a tuple of `(dir_name, file_name, line_no)`.
    ///
    /// This function is pretty much the same as `find_line_as_ref()`
    /// except returning a copies of `String` instead of `&str`.
    #[cfg(test)]
    fn find_line(&self, address: u64) -> Option<(String, String, usize)> {
        let (dir, file, line_no) = self.find_line_as_ref(address)?;
        Some((String::from(dir), String::from(file), line_no))
    }

    /// Extract the symbol information from DWARf if having not did it
    /// before.
    fn ensure_debug_info_syms(&self) -> Result<(), Error> {
        if self.enable_debug_info_syms {
            let mut dis_ref = self.debug_info_syms.borrow_mut();
            if dis_ref.is_some() {
                return Ok(());
            }
            let mut debug_info_syms = debug_info_parse_symbols(&self.parser, None, 1)?;
            debug_info_syms.sort_by_key(|v: &DWSymInfo| -> &str { v.name });
            *dis_ref = Some(unsafe { mem::transmute(debug_info_syms) });
        }
        Ok(())
    }

    /// Find the address of a symbol from DWARF.
    ///
    /// # Arguments
    ///
    /// * `name` - is the symbol name to find.
    /// * `opts` - is the context giving additional parameters.
    pub fn find_address(&self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymbolInfo>, Error> {
        if let SymbolType::Variable = opts.sym_type {
            return Err(Error::new(ErrorKind::Unsupported, "Not implemented"));
        }
        let elf_r = self.parser.find_address(name, opts)?;
        if !elf_r.is_empty() {
            // Since it is found from symtab, symtab should be
            // complete and DWARF shouldn't provide more information.
            return Ok(elf_r);
        }

        self.ensure_debug_info_syms()?;
        let dis_ref = self.debug_info_syms.borrow();
        let debug_info_syms = dis_ref.as_ref().unwrap();
        let mut idx =
            match debug_info_syms.binary_search_by_key(&name.to_string(), |v| v.name.to_string()) {
                Ok(idx) => idx,
                _ => {
                    return Ok(vec![]);
                }
            };
        while idx > 0 && debug_info_syms[idx].name.eq(name) {
            idx -= 1;
        }
        if !debug_info_syms[idx].name.eq(name) {
            idx += 1;
        }
        let mut found = vec![];
        while debug_info_syms[idx].name.eq(name) {
            let DWSymInfo {
                address,
                size,
                sym_type,
                ..
            } = debug_info_syms[idx];
            found.push(SymbolInfo {
                name: name.to_string(),
                address,
                size,
                sym_type,
                ..Default::default()
            });
            idx += 1;
        }
        Ok(found)
    }

    /// Find the address of symbols matching a pattern from DWARF.
    ///
    /// #Arguments
    ///
    /// * `pattern` - is a regex pattern to match symbols.
    /// * `opts` - is the context giving additional parameters.
    ///
    /// Return a list of symbols including addresses and other information.
    pub fn find_address_regex(
        &self,
        pattern: &str,
        opts: &FindAddrOpts,
    ) -> Result<Vec<SymbolInfo>, Error> {
        if let SymbolType::Variable = opts.sym_type {
            return Err(Error::new(ErrorKind::Unsupported, "Not implemented"));
        }
        let r = self.parser.find_address_regex(pattern, opts)?;
        if !r.is_empty() {
            return Ok(r);
        }

        self.ensure_debug_info_syms()?;

        let dis_ref = self.debug_info_syms.borrow();
        if dis_ref.is_none() {
            return Ok(vec![]);
        }
        let debug_info_syms = dis_ref.as_ref().unwrap();
        let mut syms = vec![];
        let re = Regex::new(pattern).unwrap();
        for sym in debug_info_syms {
            if re.is_match(sym.name) {
                let DWSymInfo {
                    address,
                    size,
                    sym_type,
                    ..
                } = sym;
                syms.push(SymbolInfo {
                    name: sym.name.to_string(),
                    address: *address,
                    size: *size,
                    sym_type: *sym_type,
                    ..Default::default()
                });
            }
        }

        Ok(syms)
    }

    #[cfg(test)]
    fn pick_address_for_test(&self) -> (u64, &str, &str, usize) {
        let (addr, idx) = self.addr_to_dlcu[self.addr_to_dlcu.len() / 3];
        let dlcu = &self.debug_line_cus[idx as usize];
        let (dir, file, line) = dlcu.stringify_row(0).unwrap();
        (addr, dir, file, line)
    }
}

/// The symbol information extracted out of DWARF.
#[derive(Clone)]
struct DWSymInfo<'a> {
    name: &'a str,
    address: u64,
    size: u64,
    sym_type: SymbolType, // A function or a variable.
}

fn find_die_sibling(die: &mut debug_info::DIE<'_>) -> Option<usize> {
    for (name, _form, _opt, value) in die {
        if name == constants::DW_AT_sibling {
            if let debug_info::AttrValue::Unsigned(off) = value {
                return Some(off as usize);
            }
            return None;
        }
    }
    None
}

/// Parse a DIE that declares a subprogram. (a function)
///
/// We already know the given DIE is a declaration of a subprogram.
/// This function trys to extract the address of the subprogram and
/// other information from the DIE.
///
/// # Arguments
///
/// * `die` - is a DIE.
/// * `str_data` - is the content of the `.debug_str` section.
///
/// Return a [`DWSymInfo`] if it finds the address of the subprogram.
fn parse_die_subprogram<'a>(
    die: &mut debug_info::DIE<'a>,
    str_data: &'a [u8],
) -> Result<Option<DWSymInfo<'a>>, Error> {
    let mut addr: Option<u64> = None;
    let mut name_str: Option<&str> = None;
    let mut size = 0;

    for (name, _form, _opt, value) in die {
        match name {
            constants::DW_AT_linkage_name | constants::DW_AT_name => {
                if name_str.is_some() {
                    continue;
                }
                name_str = Some(match value {
                    debug_info::AttrValue::Unsigned(str_off) => unsafe {
                        CStr::from_ptr(str_data[str_off as usize..].as_ptr() as *const i8)
                            .to_str()
                            .map_err(|_e| {
                                Error::new(
                                    ErrorKind::InvalidData,
                                    "fail to extract the name of a subprogram",
                                )
                            })?
                    },
                    debug_info::AttrValue::String(s) => s,
                    _ => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "fail to parse DW_AT_linkage_name {}",
                        ));
                    }
                });
            }
            constants::DW_AT_lo_pc => match value {
                debug_info::AttrValue::Unsigned(pc) => {
                    addr = Some(pc);
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "fail to parse DW_AT_lo_pc",
                    ));
                }
            },
            constants::DW_AT_hi_pc => match value {
                debug_info::AttrValue::Unsigned(sz) => {
                    size = sz;
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "fail to parse DW_AT_lo_pc",
                    ));
                }
            },
            _ => {}
        }
    }

    match (addr, name_str) {
        (Some(address), Some(name)) => Ok(Some(DWSymInfo {
            name,
            address,
            size,
            sym_type: SymbolType::Function,
        })),
        _ => Ok(None),
    }
}

/// Walk through all DIEs of a compile unit to extract symbols.
///
/// # Arguments
///
/// * `dieiter` - is an iterator returned by the iterator that is
///               returned by an [`UnitIter`].  [`UnitIter`] returns
///               an [`UnitHeader`] and an [`DIEIter`].
/// * `str_data` - is the content of the `.debug_str` section.
/// * `found_syms` - the Vec to append the found symbols.
fn debug_info_parse_symbols_cu<'a>(
    mut dieiter: debug_info::DIEIter<'a>,
    str_data: &'a [u8],
    found_syms: &mut Vec<DWSymInfo<'a>>,
) {
    while let Some(mut die) = dieiter.next() {
        if die.tag == 0 || die.tag == constants::DW_TAG_namespace {
            continue;
        }

        assert!(die.abbrev.is_some());
        if die.tag != constants::DW_TAG_subprogram {
            if die.abbrev.unwrap().has_children {
                if let Some(sibling_off) = find_die_sibling(&mut die) {
                    dieiter.seek_to_sibling(sibling_off);
                    continue;
                }
                // Skip this DIE quickly, or the iterator will
                // recalculate the size of the DIE.
                die.exhaust().unwrap();
            }
            continue;
        }

        if let Ok(Some(syminfo)) = parse_die_subprogram(&mut die, str_data) {
            found_syms.push(syminfo);
        }
    }
}

/// The parse result of the `.debug_info` section.
///
/// This type is used by the worker threads to pass results to the
/// coordinator after finishing an Unit.  `Stop` is used to nofity the
/// coordinator that a matching condition is met.  It could be that
/// the given symbol is already found, so that the coordinator should
/// stop producing more tasks.
enum DIParseResult<'a> {
    Symbols(Vec<DWSymInfo<'a>>),
    Stop,
}

/// Parse the addresses of symbols from the `.debug_info` section.
///
/// # Arguments
///
/// * `parser` - is an ELF parser.
/// * `cond` - is a function to check if we have found the information
///            we need.  The function will stop earlier if the
///            condition is met.
/// * `nthreads` - is the number of worker threads to create. 0 or 1
///                means single thread.
fn debug_info_parse_symbols<'a>(
    parser: &'a ElfParser,
    cond: Option<&(dyn Fn(&DWSymInfo<'a>) -> bool + Send + Sync)>,
    nthreads: usize,
) -> Result<Vec<DWSymInfo<'a>>, Error> {
    let info_sect_idx = parser.find_section(".debug_info")?;
    let info_data = parser.read_section_raw_cache(info_sect_idx)?;
    let abbrev_sect_idx = parser.find_section(".debug_abbrev")?;
    let abbrev_data = parser.read_section_raw_cache(abbrev_sect_idx)?;
    let units = debug_info::UnitIter::new(info_data, abbrev_data);
    let str_sect_idx = parser.find_section(".debug_str")?;
    let str_data = parser.read_section_raw_cache(str_sect_idx)?;

    let mut syms = Vec::<DWSymInfo>::new();

    if nthreads > 1 {
        thread::scope(|s| {
            // Create worker threads to process tasks (Units) in a work
            // queue.
            let mut handles = vec![];
            let (qsend, qrecv) = unbounded::<debug_info::DIEIter<'a>>();
            let (result_tx, result_rx) = mpsc::channel::<DIParseResult>();

            for _ in 0..nthreads {
                let result_tx = result_tx.clone();
                let qrecv = qrecv.clone();

                let handle = s.spawn(move || {
                    let mut syms: Vec<DWSymInfo> = vec![];
                    if let Some(cond) = cond {
                        while let Ok(dieiterholder) = qrecv.recv() {
                            let saved_sz = syms.len();
                            debug_info_parse_symbols_cu(dieiterholder, str_data, &mut syms);
                            for sym in &syms[saved_sz..] {
                                if !cond(sym) {
                                    result_tx.send(DIParseResult::Stop).unwrap();
                                }
                            }
                        }
                    } else {
                        while let Ok(dieiterholder) = qrecv.recv() {
                            debug_info_parse_symbols_cu(dieiterholder, str_data, &mut syms);
                        }
                    }
                    result_tx.send(DIParseResult::Symbols(syms)).unwrap();
                });

                handles.push(handle);
            }

            for (uhdr, dieiter) in units {
                if let debug_info::UnitHeader::CompileV4(_) = uhdr {
                    qsend.send(dieiter).unwrap();
                }

                if let Ok(result) = result_rx.try_recv() {
                    if let DIParseResult::Stop = result {
                        break;
                    } else {
                        return Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "Receive an unexpected result",
                        ));
                    }
                }
            }

            drop(qsend);

            drop(result_tx);
            while let Ok(result) = result_rx.recv() {
                if let DIParseResult::Symbols(mut thread_syms) = result {
                    syms.append(&mut thread_syms);
                }
            }
            for handle in handles {
                handle.join().unwrap();
            }
            Ok(())
        })?;
    } else if let Some(cond) = cond {
        'outer: for (uhdr, dieiter) in units {
            if let debug_info::UnitHeader::CompileV4(_) = uhdr {
                let saved_sz = syms.len();
                debug_info_parse_symbols_cu(dieiter, str_data, &mut syms);
                for sym in &syms[saved_sz..] {
                    if !cond(sym) {
                        break 'outer;
                    }
                }
            }
        }
    } else {
        for (uhdr, dieiter) in units {
            if let debug_info::UnitHeader::CompileV4(_) = uhdr {
                debug_info_parse_symbols_cu(dieiter, str_data, &mut syms);
            }
        }
    }
    Ok(syms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "nightly")]
    use test::Bencher;


    fn parse_debug_line_elf(filename: &Path) -> Result<Vec<DebugLineCU>, Error> {
        let parser = ElfParser::open(filename)?;
        parse_debug_line_elf_parser(&parser, &[])
    }

    #[allow(unused)]
    struct ArangesCU {
        debug_line_off: usize,
        aranges: Vec<(u64, u64)>,
    }

    fn parse_aranges_cu(data: &[u8]) -> Result<(ArangesCU, usize), Error> {
        if data.len() < 12 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid arange header (too small)",
            ));
        }
        let len = decode_uword(data);
        let version = decode_uhalf(&data[4..]);
        let offset = decode_uword(&data[6..]);
        let addr_sz = data[10];
        let _seg_sz = data[11];

        if data.len() < (len + 4) as usize {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "data is broken (too small)",
            ));
        }

        // Size of the header
        let mut pos = 12;

        // Padding to align with the size of addresses on the target system.
        pos += addr_sz as usize - 1;
        pos -= pos % addr_sz as usize;

        let mut aranges = Vec::<(u64, u64)>::new();
        match addr_sz {
            4 => {
                while pos < (len + 4 - 8) as usize {
                    let start = decode_uword(&data[pos..]);
                    pos += 4;
                    let size = decode_uword(&data[pos..]);
                    pos += 4;

                    if start == 0 && size == 0 {
                        break;
                    }
                    aranges.push((start as u64, size as u64));
                }
            }
            8 => {
                while pos < (len + 4 - 16) as usize {
                    let start = decode_udword(&data[pos..]);
                    pos += 8;
                    let size = decode_udword(&data[pos..]);
                    pos += 8;

                    if start == 0 && size == 0 {
                        break;
                    }
                    aranges.push((start, size));
                }
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    format!("unsupported address size {addr_sz} ver {version} off 0x{offset:x}"),
                ));
            }
        }

        Ok((
            ArangesCU {
                debug_line_off: offset as usize,
                aranges,
            },
            len as usize + 4,
        ))
    }

    fn parse_aranges_elf_parser(parser: &ElfParser) -> Result<Vec<ArangesCU>, Error> {
        let debug_aranges_idx = parser.find_section(".debug_aranges")?;

        let raw_data = parser.read_section_raw(debug_aranges_idx)?;

        let mut pos = 0;
        let mut acus = Vec::<ArangesCU>::new();
        while pos < raw_data.len() {
            let (acu, bytes) = parse_aranges_cu(&raw_data[pos..])?;
            acus.push(acu);
            pos += bytes;
        }

        Ok(acus)
    }

    fn parse_aranges_elf(filename: &Path) -> Result<Vec<ArangesCU>, Error> {
        let parser = ElfParser::open(filename)?;
        parse_aranges_elf_parser(&parser)
    }

    #[test]
    fn test_parse_debug_line_elf() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-dwarf-v4.bin");

        let _ = parse_debug_line_elf(bin_name.as_ref()).unwrap();
    }

    #[test]
    fn test_run_debug_line_stmts_1() {
        let stmts = [
            0x00, 0x09, 0x02, 0x30, 0x8b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xa0, 0x04,
            0x01, 0x05, 0x06, 0x0a, 0x08, 0x30, 0x02, 0x05, 0x00, 0x01, 0x01,
        ];
        let prologue = DebugLinePrologue {
            total_length: 0,
            version: 4,
            prologue_length: 0,
            minimum_instruction_length: 1,
            maximum_ops_per_instruction: 1,
            default_is_stmt: 1,
            line_base: -5,
            line_range: 14,
            opcode_base: 13,
        };

        let result = run_debug_line_stmts(&stmts, &prologue, &[]);
        if result.is_err() {
            let e = result.as_ref().err().unwrap();
            println!("result {e:?}");
        }
        assert!(result.is_ok());
        let matrix = result.unwrap();
        assert_eq!(matrix.len(), 3);
        assert_eq!(matrix[0].line, 545);
        assert_eq!(matrix[0].address, 0x18b30);
        assert_eq!(matrix[1].line, 547);
        assert_eq!(matrix[1].address, 0x18b43);
        assert_eq!(matrix[2].line, 547);
        assert_eq!(matrix[2].address, 0x18b48);
    }

    #[test]
    fn test_run_debug_line_stmts_2() {
        //	File name                            Line number    Starting address    View    Stmt
        //	    methods.rs                                   789             0x18c70               x
        //	    methods.rs                                   791             0x18c7c               x
        //	    methods.rs                                   791             0x18c81
        //	    methods.rs                                   790             0x18c86               x
        //	    methods.rs                                     0             0x18c88
        //	    methods.rs                                   791             0x18c8c               x
        //	    methods.rs                                     0             0x18c95
        //	    methods.rs                                   792             0x18c99               x
        //	    methods.rs                                   792             0x18c9d
        //	    methods.rs                                     0             0x18ca4
        //	    methods.rs                                   791             0x18ca8               x
        //	    methods.rs                                   792             0x18caf               x
        //	    methods.rs                                     0             0x18cb6
        //	    methods.rs                                   792             0x18cba
        //	    methods.rs                                     0             0x18cc4
        //	    methods.rs                                   792             0x18cc8
        //	    methods.rs                                   790             0x18cce               x
        //	    methods.rs                                   794             0x18cd0               x
        //	    methods.rs                                   794             0x18cde               x
        let stmts = [
            0x00, 0x09, 0x02, 0x70, 0x8c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x94, 0x06,
            0x01, 0x05, 0x0d, 0x0a, 0xbc, 0x05, 0x26, 0x06, 0x58, 0x05, 0x09, 0x06, 0x57, 0x06,
            0x03, 0xea, 0x79, 0x2e, 0x05, 0x13, 0x06, 0x03, 0x97, 0x06, 0x4a, 0x06, 0x03, 0xe9,
            0x79, 0x90, 0x05, 0x0d, 0x06, 0x03, 0x98, 0x06, 0x4a, 0x05, 0x12, 0x06, 0x4a, 0x03,
            0xe8, 0x79, 0x74, 0x05, 0x13, 0x06, 0x03, 0x97, 0x06, 0x4a, 0x05, 0x12, 0x75, 0x06,
            0x03, 0xe8, 0x79, 0x74, 0x05, 0x20, 0x03, 0x98, 0x06, 0x4a, 0x03, 0xe8, 0x79, 0x9e,
            0x05, 0x12, 0x03, 0x98, 0x06, 0x4a, 0x05, 0x09, 0x06, 0x64, 0x05, 0x06, 0x32, 0x02,
            0x0e, 0x00, 0x01, 0x01,
        ];
        let prologue = DebugLinePrologue {
            total_length: 0,
            version: 4,
            prologue_length: 0,
            minimum_instruction_length: 1,
            maximum_ops_per_instruction: 1,
            default_is_stmt: 1,
            line_base: -5,
            line_range: 14,
            opcode_base: 13,
        };

        let result = run_debug_line_stmts(&stmts, &prologue, &[]);
        if result.is_err() {
            let e = result.as_ref().err().unwrap();
            println!("result {e:?}");
        }
        assert!(result.is_ok());
        let matrix = result.unwrap();

        assert_eq!(matrix.len(), 19);
        assert_eq!(matrix[0].line, 789);
        assert_eq!(matrix[0].address, 0x18c70);
        assert!(matrix[0].is_stmt);

        assert_eq!(matrix[1].line, 791);
        assert_eq!(matrix[1].address, 0x18c7c);
        assert!(matrix[1].is_stmt);

        assert_eq!(matrix[2].line, 791);
        assert_eq!(matrix[2].address, 0x18c81);
        assert!(!matrix[2].is_stmt);

        assert_eq!(matrix[13].line, 792);
        assert_eq!(matrix[13].address, 0x18cba);
        assert!(!matrix[13].is_stmt);

        assert_eq!(matrix[14].line, 0);
        assert_eq!(matrix[14].address, 0x18cc4);
        assert!(!matrix[14].is_stmt);

        assert_eq!(matrix[18].line, 794);
        assert_eq!(matrix[18].address, 0x18cde);
        assert!(matrix[18].is_stmt);
    }

    #[test]
    fn test_parse_aranges_elf() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-dwarf-v4.bin");

        let _aranges = parse_aranges_elf(bin_name.as_ref()).unwrap();
    }

    #[test]
    fn test_dwarf_resolver() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-dwarf-v4.bin");
        let resolver = DwarfResolver::open(bin_name.as_ref(), true, false).unwrap();
        let (addr, dir, file, line) = resolver.pick_address_for_test();

        let (dir_ret, file_ret, line_ret) = resolver.find_line(addr).unwrap();
        assert_eq!(dir, dir_ret);
        assert_eq!(file, file_ret);
        assert_eq!(line, line_ret);
    }

    #[test]
    fn test_debug_info_parse_symbols() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-dwarf-v4.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        let syms = debug_info_parse_symbols(&parser, None, 4).unwrap();
        assert!(syms.iter().any(|sym| sym.name == "fibonacci"))
    }

    #[test]
    fn test_dwarf_find_addr_regex() {
        let bin_name = env::args().next().unwrap();
        let dwarf = DwarfResolver::open(bin_name.as_ref(), false, true).unwrap();
        let opts = FindAddrOpts {
            offset_in_file: false,
            obj_file_name: false,
            sym_type: SymbolType::Unknown,
        };
        let syms = dwarf
            .find_address_regex("DwarfResolver.*find_address_regex.*", &opts)
            .unwrap();
        assert!(!syms.is_empty());
    }

    /// Benchmark the [`debug_info_parse_symbols`] function.
    #[cfg(feature = "nightly")]
    #[bench]
    fn debug_info_parse_single_threaded(b: &mut Bencher) {
        let bin_name = env::args().next().unwrap();
        let parser = ElfParser::open(bin_name.as_ref()).unwrap();

        let () = b.iter(|| debug_info_parse_symbols(&parser, None, 1).unwrap());
    }
}
