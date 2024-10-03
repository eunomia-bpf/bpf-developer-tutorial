//! Parser of GSYM format.
//!
//! The layout of a standalone GSYM contains following sections in the order.
//!
//! * Header
//! * Address Table
//! * Address Data Offset Table
//! * File Table
//! * String Table
//! * Address Data
//!
//! The standalone GSYM starts with a Header, which describes the
//! size of an entry in the address table, the number of entries in
//! the address table, and the location and the size of the string
//! table.
//!
//! Since the Address Table is immediately after the Header, the
//! Header describes only the size of an entry and number of entries
//! in the table but not where it is.  The Address Table comprises
//! addresses of symbols in the ascending order, so we can find the
//! symbol an address belonging to by doing a binary search to find
//! the most close address but smaller or equal.
//!
//! The Address Data Offset Table has the same number of entries as
//! the Address Table.  Every entry in one table will has
//! corresponding entry at the same offset in the other table.  The
//! entries in the Address Data Offset Table are always 32bits
//! (4bytes.)  It is the file offset to the respective Address
//! Data. (AddressInfo actually)
//!
//! An AddressInfo comprises the size and name of a symbol.  The name
//! is an offset in the string table.  You will find a null terminated
//! C string at the give offset.  The size is the number of bytes of
//! the respective object; ex, a function or variable.
//!
//! See <https://reviews.llvm.org/D53379>

use std::ffi::CStr;
use std::io::{Error, ErrorKind};

use crate::util::decode_leb128;
use crate::util::decode_leb128_s;
use crate::util::decode_udword;
use crate::util::decode_uhalf;
use crate::util::decode_uword;

use super::linetab::LineTableHeader;
use super::types::AddressData;
use super::types::AddressInfo;
use super::types::FileInfo;
use super::types::Header;
use super::types::InfoTypeEndOfList;
use super::types::InfoTypeInlineInfo;
use super::types::InfoTypeLineTableInfo;
use super::types::ADDR_DATA_OFFSET_SIZE;
use super::types::FILE_INFO_SIZE;
use super::types::GSYM_MAGIC;
use super::types::GSYM_VERSION;

/// Hold the major parts of a standalone GSYM file.
///
/// GsymContext provides functions to access major entities in GSYM.
/// GsymContext can find respective AddressInfo for an address.  But,
/// it doesn't parse AddressData to get line numbers.
///
/// The developers should use [`parse_address_data()`],
/// [`parse_line_table_header()`], and [`linetab::run_op()`] to get
/// line number information from [`AddressInfo`].
pub struct GsymContext<'a> {
    header: Header,
    addr_tab: &'a [u8],
    addr_data_off_tab: &'a [u8],
    file_tab: &'a [u8],
    str_tab: &'a [u8],
    raw_data: &'a [u8],
}

impl<'a> GsymContext<'a> {
    /// Parse the Header of a standalone GSYM file.
    ///
    /// # Arguments
    ///
    /// * `data` - is the content of a standalone GSYM.
    ///
    /// Returns a GsymContext, which includes the Header and other important tables.
    pub fn parse_header(data: &[u8]) -> Result<GsymContext, Error> {
        let mut off = 0;
        // Parse Header
        let magic = decode_uword(data);
        if magic != GSYM_MAGIC {
            return Err(Error::new(ErrorKind::InvalidData, "invalid magic number"));
        }
        off += 4;
        let version = decode_uhalf(&data[off..]);
        if version != GSYM_VERSION {
            return Err(Error::new(ErrorKind::InvalidData, "unknown version number"));
        }
        off += 2;
        let addr_off_size = data[off];
        off += 1;
        let uuid_size = data[off];
        off += 1;
        let base_address = decode_udword(&data[off..]);
        off += 8;
        let num_addrs = decode_uword(&data[off..]);
        off += 4;
        let strtab_offset = decode_uword(&data[off..]);
        off += 4;
        let strtab_size = decode_uword(&data[off..]);
        off += 4;
        let uuid: [u8; 20] = (&data[off..(off + 20)])
            .try_into()
            .expect("input data is too short");
        off += 20;

        // Get the slices of the Address Table, Address Data Offset Table,
        // and String table.
        let end_off = off + num_addrs as usize * addr_off_size as usize;
        if end_off > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "the size of the file is smaller than expectation (address table)",
            ));
        }
        let addr_tab = &data[off..end_off];
        off = (end_off + 0x3) & !0x3;
        let end_off = off + num_addrs as usize * ADDR_DATA_OFFSET_SIZE;
        if end_off > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "the size of the file is smaller than expectation (address data offset table)",
            ));
        }
        let addr_data_off_tab = &data[off..end_off];
        off += num_addrs as usize * ADDR_DATA_OFFSET_SIZE;
        let file_num = decode_uword(&data[off..]);
        off += 4;
        let end_off = off + file_num as usize * FILE_INFO_SIZE;
        if end_off > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "the size of the file is smaller than expectation (file table)",
            ));
        }
        let file_tab = &data[off..end_off];
        let end_off = strtab_offset as usize + strtab_size as usize;
        if end_off > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "the size of the file is smaller than expectation (string table)",
            ));
        }
        let str_tab = &data[strtab_offset as usize..end_off];

        Ok(GsymContext {
            header: Header {
                magic,
                version,
                addr_off_size,
                uuid_size,
                base_address,
                num_addrs,
                strtab_offset,
                strtab_size,
                uuid,
            },
            addr_tab,
            addr_data_off_tab,
            file_tab,
            str_tab,
            raw_data: data,
        })
    }

    pub fn num_addresses(&self) -> usize {
        self.header.num_addrs as usize
    }

    /// Get the address of an entry in the Address Table.
    pub fn addr_at(&self, idx: usize) -> Option<u64> {
        if idx >= self.header.num_addrs as usize {
            return None;
        }

        let off = idx * self.header.addr_off_size as usize;
        let mut addr = 0u64;
        let mut shift = 0;
        for d in &self.addr_tab[off..(off + self.header.addr_off_size as usize)] {
            addr |= (*d as u64) << shift;
            shift += 8;
        }
        addr += self.header.base_address;
        Some(addr)
    }

    /// Get the AddressInfo of an address given by an index.
    pub fn addr_info(&self, idx: usize) -> Option<AddressInfo> {
        if idx >= self.header.num_addrs as usize {
            return None;
        }

        let off = idx * ADDR_DATA_OFFSET_SIZE;
        let ad_off = decode_uword(&self.addr_data_off_tab[off..]) as usize;
        let size = decode_uword(&self.raw_data[ad_off..]);
        let name = decode_uword(&self.raw_data[ad_off + 4..]);
        let info = AddressInfo {
            size,
            name,
            data: &self.raw_data[ad_off + 8..],
        };

        Some(info)
    }

    /// Get the string at the given offset from the String Table.
    pub fn get_str(&self, off: usize) -> Option<&str> {
        if off >= self.str_tab.len() {
            return None;
        }

        // Ensure there is a null byte.
        let mut null_off = self.str_tab.len() - 1;
        while null_off > off && self.str_tab[null_off] != 0 {
            null_off -= 1;
        }
        if null_off == off {
            return Some("");
        }

        // SAFETY: the lifetime of `CStr` can live as long as `self`.
        // The returned reference can also live as long as `self`.
        unsafe {
            CStr::from_ptr(self.str_tab[off..].as_ptr() as *const i8)
                .to_str()
                .ok()
        }
    }

    pub fn file_info(&self, idx: usize) -> Option<FileInfo> {
        if idx >= self.file_tab.len() / FILE_INFO_SIZE {
            return None;
        }
        let mut off = idx * FILE_INFO_SIZE;
        let directory = decode_uword(&self.file_tab[off..(off + 4)]);
        off += 4;
        let filename = decode_uword(&self.file_tab[off..(off + 4)]);
        let info = FileInfo {
            directory,
            filename,
        };
        Some(info)
    }
}

/// Find the index of an entry in the address table most likely
/// containing the given address.
///
/// The callers should check the respective `AddressInfo` to make sure
/// it is what they request for.
pub fn find_address(ctx: &GsymContext, addr: u64) -> Option<usize> {
    let mut left = 0;
    let mut right = ctx.num_addresses();

    if right == 0 {
        return None;
    }
    if addr < ctx.addr_at(0)? {
        return None;
    }

    while (left + 1) < right {
        let v = (left + right) / 2;
        let cur_addr = ctx.addr_at(v)?;

        if addr == cur_addr {
            return Some(v);
        }
        if addr < cur_addr {
            right = v;
        } else {
            left = v;
        }
    }
    Some(left)
}

/// Parse AddressData.
///
/// AddressDatas are items following AndressInfo.
/// [`GsymContext::addr_info()`] returns the raw data of AddressDatas as a
/// slice at [`AddressInfo::data`].
///
/// # Arguments
///
/// * `data` - is the slice from AddressInfo::data.
///
/// Returns a vector of [`AddressData`].
pub fn parse_address_data(data: &[u8]) -> Vec<AddressData> {
    let mut data_objs = vec![];

    let mut off = 0;
    while off < data.len() {
        let typ = decode_uword(&data[off..]);
        off += 4;
        let length = decode_uword(&data[off..]);
        off += 4;
        let d = &data[off..(off + length as usize)];
        data_objs.push(AddressData {
            typ,
            length,
            data: d,
        });
        off += length as usize;

        #[allow(non_upper_case_globals)]
        match typ {
            InfoTypeEndOfList => {
                break;
            }
            InfoTypeLineTableInfo | InfoTypeInlineInfo => {}
            _ => {
                #[cfg(debug_assertions)]
                eprintln!("unknown info type");
            }
        }
    }

    data_objs
}

/// Parse AddressData of InfoTypeLineTableInfo.
///
/// An `AddressData` of `InfoTypeLineTableInfo` type is a table of line numbers
/// for a symbol. `AddressData` is the payload of `AddressInfo`. One
/// `AddressInfo` may have several `AddressData` entries in its payload. Each
/// `AddressData` entry stores a type of data relates to the symbol the
/// `AddressInfo` presents.
///
/// # Arguments
///
/// * `data` - is what [`AddressData::data`] is.
///
/// Returns the `LineTableHeader` and the size of the header of a
/// `AddressData` entry of `InfoTypeLineTableInfo` type in the payload
/// of an `Addressinfo`.
pub fn parse_line_table_header(data: &[u8]) -> Option<(LineTableHeader, usize)> {
    let mut off = 0;
    let (min_delta, bytes) = decode_leb128_s(&data[off..])?;
    off += bytes as usize;
    let (max_delta, bytes) = decode_leb128_s(&data[off..])?;
    off += bytes as usize;
    let (first_line, bytes) = decode_leb128(&data[off..])?;
    off += bytes as usize;

    let header = LineTableHeader {
        min_delta,
        max_delta,
        first_line: first_line as u32,
    };
    Some((header, off))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::path::Path;


    #[test]
    fn test_parse_context() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.gsym");
        let mut gsym_fo = File::open(test_gsym).unwrap();
        let mut data = vec![];

        gsym_fo.read_to_end(&mut data).unwrap();
        let ctx = GsymContext::parse_header(&data).unwrap();

        let idx = find_address(&ctx, 0x0000000002000000).unwrap();
        let addrinfo = ctx.addr_info(idx).unwrap();
        assert_eq!(ctx.get_str(addrinfo.name as usize).unwrap(), "main");

        let idx = find_address(&ctx, 0x0000000002000100).unwrap();
        let addrinfo = ctx.addr_info(idx).unwrap();
        assert_eq!(ctx.get_str(addrinfo.name as usize).unwrap(), "factorial");
    }

    #[test]
    fn test_find_address() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.gsym");
        let mut gsym_fo = File::open(test_gsym).unwrap();
        let mut data = vec![];

        const TEST_SIZE: usize = 6;

        gsym_fo.read_to_end(&mut data).unwrap();

        let mut addr_tab = Vec::<u8>::new();
        addr_tab.resize(TEST_SIZE * 4, 0);

        let mut values: Vec<u32> = (0_u32..(TEST_SIZE as u32)).collect();

        let copy_to_addr_tab = |values: &[u32], addr_tab: &mut Vec<u8>| {
            addr_tab.clear();
            for v in values {
                let r = addr_tab.write(&v.to_ne_bytes());
                assert!(r.is_ok());
            }
        };
        // Generate all possible sequences that values are in strictly
        // ascending order and `< TEST_SIZE * 2`.
        let gen_values = |values: &mut [u32]| {
            let mut carry_out = TEST_SIZE as u32 * 2;
            for i in (0..values.len()).rev() {
                values[i] += 1;
                if values[i] >= carry_out {
                    carry_out -= 1;
                    continue;
                }
                // Make all values at right side minimal and strictly
                // ascending.
                for j in (i + 1)..values.len() {
                    values[j] = values[j - 1] + 1;
                }
                break;
            }
        };

        while values[0] <= TEST_SIZE as u32 {
            copy_to_addr_tab(&values, &mut addr_tab);

            for addr in 0..(TEST_SIZE * 2) {
                let addr_tab = addr_tab.clone();
                let mut ctx = GsymContext::parse_header(&data).unwrap();
                ctx.header.num_addrs = TEST_SIZE as u32;
                ctx.header.addr_off_size = 4;
                ctx.header.base_address = 0;
                ctx.addr_tab = addr_tab.as_slice();

                let idx = find_address(&ctx, addr as u64).unwrap_or(0);
                let addr_u32 = addr as u32;
                let idx1 = match values.binary_search(&addr_u32) {
                    Ok(idx) => idx,
                    Err(idx) => {
                        // When the searching value is falling in
                        // between two values, it will return the
                        // index of the later one. But we want the
                        // earlier one.
                        if idx > 0 {
                            idx - 1
                        } else {
                            0
                        }
                    }
                };
                assert_eq!(idx, idx1);
            }

            gen_values(&mut values);
        }
    }
}
