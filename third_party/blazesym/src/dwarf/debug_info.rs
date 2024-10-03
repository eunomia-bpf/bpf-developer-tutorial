//! Parse the `.debug_info` section to get Debug Information Entries.
//!
//! It supports DWARFv4 now. (See <https://dwarfstd.org/doc/DWARF4.pdf>)
//! It parse DIEs from the `.debug_info` section and Abbreviations
//! from the `.debg_abbrev` section.
//!
//! The `.debug_info` section is a list of (Compile-)Units.  Every
//! Unit comprises DIEs to carry debug information of a source file.
//! A Unit starts with a header to describe the size of this unit in
//! the section, the offset of its abbreviation table in the
//! `.debug_abbrev` section, ..., and DWARF version. (version 4)
//!
//! A DIE starts with an index encoded in LEB128 to the abbreviation
//! table of the Unit.  The abbreviation given by the index describle
//! the content, format and layout of a DIE.  The abbreviation index
//! starts from 1.  0 means a null entry.  DIEs in an Unit are
//! organized as a tree, parent-children.  Null entries are used to
//! signal the last sibling to end a level.
//!
//! A user starts a parser by creating an instance of [`UnitIter`].
//! It will walk through the data in the `.debug_info` and
//! `.debug_abbrev` section to return Units.

use std::io::{Error, ErrorKind};
use std::iter::Iterator;
use std::mem;

use crate::util::decode_leb128_128;
use crate::util::decode_udword;
use crate::util::decode_uhalf;
use crate::util::decode_uword;
use crate::util::ReadRaw as _;

use super::constants::*;


fn read_3bytes(data: &mut &[u8]) -> Option<u32> {
    if let [b1, b2, b3] = data.read_slice(3)? {
        Some(*b1 as u32 | ((*b2 as u32) << 8) | ((*b3 as u32) << 16))
    } else {
        unreachable!()
    }
}

#[allow(unused)]
pub struct UnknownHeader {
    init_length: usize,
    bits64: bool,
    version: u16,
    unit_type: u8,
    hdr_size: usize,
}

#[allow(unused)]
pub struct CUHeaderV5 {
    init_length: usize,
    bits64: bool,
    version: u16,
    unit_type: u8,
    address_size: u8,
    debug_abbrev_offset: u64,
    hdr_size: usize,
}

#[allow(unused)]
pub struct CUHeaderV4 {
    init_length: usize,
    bits64: bool,
    version: u16,
    address_size: u8,
    debug_abbrev_offset: u64, // The location of the abbreviation table.
    hdr_size: usize,
}

/// The Unit header.
///
/// With DWARFv4, an unit header describe a compile unit followed by
/// DIEs of the unit in the `.debug_info` section.  DWARFv5 is much
/// more complicated.
///
/// So far, BlazeSym supports only DWARFv4, that is common used.
pub enum UnitHeader {
    CompileV4(CUHeaderV4),
    CompileV5(CUHeaderV5),
    Unknown(UnknownHeader),
}

impl UnitHeader {
    fn unit_size(&self) -> usize {
        match self {
            UnitHeader::CompileV4(h) => h.init_length + (if h.bits64 { 12 } else { 4 }),
            UnitHeader::CompileV5(h) => h.init_length + (if h.bits64 { 12 } else { 4 }),
            UnitHeader::Unknown(h) => h.init_length + (if h.bits64 { 12 } else { 4 }),
        }
    }

    fn header_size(&self) -> usize {
        match self {
            UnitHeader::CompileV4(h) => h.hdr_size,
            UnitHeader::CompileV5(h) => h.hdr_size,
            UnitHeader::Unknown(h) => h.hdr_size,
        }
    }
}

#[derive(Clone)]
pub struct AbbrevAttr {
    name: u8,
    form: u8,
    opt: u128,
}

/// An abbreviation.
///
/// An abbrivation describes the format of a DIE.  it comprises a list
/// of specifications that describe the names and the formats of
/// attributes.  A DIE will be formated in the way described by it's
/// abbreviation.
pub struct Abbrev {
    /// The index to the abbreviation table.
    pub abbrev_code: u32,
    /// The type of the abbreviation.
    ///
    /// It can be a DW_TAG_compile (a compile unit),
    /// DW_TAG_subprogram, DW_TAG_variable, ... etc.
    pub tag: u8,
    pub has_children: bool,

    parsed_attrs: Vec<AbbrevAttr>,
}

impl Abbrev {
    #[inline]
    pub fn all_attrs(&self) -> &[AbbrevAttr] {
        &self.parsed_attrs[..]
    }
}

/// Parse an abbreviation from a buffer.
///
/// Include all attributes, names and forms.
#[inline]
fn parse_abbrev(data: &[u8]) -> Option<(Abbrev, usize)> {
    let (abbrev_code, bytes) = decode_leb128_128(data)?;
    if abbrev_code == 0 {
        return Some((
            Abbrev {
                abbrev_code: 0,
                tag: 0,
                has_children: false,
                parsed_attrs: vec![],
            },
            1,
        ));
    }

    let mut pos = bytes as usize;
    let (tag, bytes) = decode_leb128_128(&data[pos..])?;
    pos += bytes as usize;
    let has_children = data[pos] == DW_CHILDREN_yes;
    pos += 1;

    let mut parsed_attrs = Vec::<AbbrevAttr>::new();
    while pos < data.len() {
        if let Some((name, form, opt, bytes)) = parse_abbrev_attr(&data[pos..]) {
            pos += bytes;
            parsed_attrs.push(AbbrevAttr { name, form, opt });
            if form == 0 {
                break;
            }
        } else {
            break;
        }
    }

    Some((
        Abbrev {
            abbrev_code: abbrev_code as u32,
            tag: tag as u8,
            has_children,
            parsed_attrs,
        },
        pos,
    ))
}

/// Parse an attribute specification from a buffer.
///
/// Return the name, form, optional value and size of an abbreviation.
#[inline]
fn parse_abbrev_attr(data: &[u8]) -> Option<(u8, u8, u128, usize)> {
    let mut pos = 0; // Track the size of this abbreviation.
    let (name, bytes) = decode_leb128_128(&data[pos..])?;
    pos += bytes as usize;
    let (form, bytes) = decode_leb128_128(&data[pos..])?;
    pos += bytes as usize;
    let opt = if form as u8 == DW_FORM_implicit_const || form as u8 == DW_FORM_indirect {
        let (c, bytes) = decode_leb128_128(&data[pos..])?;
        pos += bytes as usize;
        c
    } else {
        0
    };
    Some((name as u8, form as u8, opt, pos))
}

#[derive(Clone, Debug)]
pub enum AttrValue<'a> {
    Signed128(i128),
    Unsigned(u64),
    Unsigned128(u128),
    Bytes(&'a [u8]),
    String(&'a str),
}

fn extract_attr_value_impl<'data>(
    data: &mut &'data [u8],
    form: u8,
    dwarf_sz: usize,
    addr_sz: usize,
) -> Option<AttrValue<'data>> {
    match form {
        DW_FORM_addr => {
            if addr_sz == 0x4 {
                Some(AttrValue::Unsigned(data.read_u32()? as u64))
            } else {
                Some(AttrValue::Unsigned(data.read_u64()?))
            }
        }
        DW_FORM_block2 => {
            let value = data.read_u16()?;
            Some(AttrValue::Bytes(data.read_slice(value.into())?))
        }
        DW_FORM_block4 => {
            let value = data.read_u32()?;
            Some(AttrValue::Bytes(data.read_slice(value as usize)?))
        }
        DW_FORM_data2 => Some(AttrValue::Unsigned(data.read_u16()?.into())),
        DW_FORM_data4 => Some(AttrValue::Unsigned(data.read_u32()?.into())),
        DW_FORM_data8 => Some(AttrValue::Unsigned(data.read_u64()?)),
        DW_FORM_string => {
            let string = data.read_cstr()?;
            Some(AttrValue::String(string.to_str().ok()?))
        }
        DW_FORM_block => {
            let (value, _bytes) = data.read_u128_leb128()?;
            Some(AttrValue::Bytes(data.read_slice(value as usize)?))
        }
        DW_FORM_block1 => {
            let value = data.read_u8()?;
            Some(AttrValue::Bytes(data.read_slice(value.into())?))
        }
        DW_FORM_data1 => Some(AttrValue::Unsigned(data.read_u8()?.into())),
        DW_FORM_flag => Some(AttrValue::Unsigned(data.read_u8()?.into())),
        DW_FORM_sdata => {
            let (value, _bytes) = data.read_i128_leb128()?;
            Some(AttrValue::Signed128(value))
        }
        DW_FORM_strp => {
            if dwarf_sz == 0x4 {
                Some(AttrValue::Unsigned(data.read_u32()?.into()))
            } else {
                Some(AttrValue::Unsigned(data.read_u64()?))
            }
        }
        DW_FORM_udata => {
            let (value, _bytes) = data.read_u128_leb128()?;
            Some(AttrValue::Unsigned128(value))
        }
        DW_FORM_ref_addr => {
            if dwarf_sz == 0x4 {
                Some(AttrValue::Unsigned(data.read_u32()?.into()))
            } else {
                Some(AttrValue::Unsigned(data.read_u64()?))
            }
        }
        DW_FORM_ref1 => Some(AttrValue::Unsigned(data.read_u8()?.into())),
        DW_FORM_ref2 => Some(AttrValue::Unsigned(data.read_u16()?.into())),
        DW_FORM_ref4 => Some(AttrValue::Unsigned(data.read_u32()?.into())),
        DW_FORM_ref8 => Some(AttrValue::Unsigned(data.read_u64()?)),
        DW_FORM_ref_udata => {
            let (value, _bytes) = data.read_u128_leb128()?;
            Some(AttrValue::Unsigned128(value))
        }
        DW_FORM_indirect => {
            let (f, _bytes) = data.read_u128_leb128()?;
            extract_attr_value_impl(data, f as u8, dwarf_sz, addr_sz)
        }
        DW_FORM_sec_offset => {
            if dwarf_sz == 0x4 {
                Some(AttrValue::Unsigned(data.read_u32()?.into()))
            } else {
                Some(AttrValue::Unsigned(data.read_u64()?))
            }
        }
        DW_FORM_exprloc => {
            let (value, _bytes) = data.read_u128_leb128()?;
            Some(AttrValue::Bytes(data.read_slice(value as usize)?))
        }
        DW_FORM_flag_present => Some(AttrValue::Unsigned(0)),
        DW_FORM_strx => {
            let (value, _bytes) = data.read_u128_leb128()?;
            Some(AttrValue::Unsigned(value as u64))
        }
        DW_FORM_addrx => {
            let (value, _bytes) = data.read_u128_leb128()?;
            Some(AttrValue::Unsigned(value as u64))
        }
        DW_FORM_ref_sup4 => Some(AttrValue::Unsigned(data.read_u32()?.into())),
        DW_FORM_strp_sup => {
            if dwarf_sz == 0x4 {
                Some(AttrValue::Unsigned(data.read_u32()?.into()))
            } else {
                Some(AttrValue::Unsigned(data.read_u64()?))
            }
        }
        DW_FORM_data16 => Some(AttrValue::Bytes(data.read_slice(16)?)),
        DW_FORM_line_strp => {
            if dwarf_sz == 0x4 {
                Some(AttrValue::Unsigned(data.read_u32()?.into()))
            } else {
                Some(AttrValue::Unsigned(data.read_u64()?))
            }
        }
        DW_FORM_ref_sig8 => Some(AttrValue::Bytes(data.read_slice(8)?)),
        DW_FORM_implicit_const => Some(AttrValue::Unsigned(0)),
        DW_FORM_loclistx => {
            let (value, _bytes) = data.read_u128_leb128()?;
            Some(AttrValue::Unsigned(value as u64))
        }
        DW_FORM_rnglistx => {
            let (value, _bytes) = data.read_u128_leb128()?;
            Some(AttrValue::Unsigned(value as u64))
        }
        DW_FORM_ref_sup8 => Some(AttrValue::Unsigned(data.read_u64()?)),
        DW_FORM_str1 => Some(AttrValue::Unsigned(data.read_u8()?.into())),
        DW_FORM_str2 => Some(AttrValue::Unsigned(data.read_u16()?.into())),
        DW_FORM_str3 => Some(AttrValue::Unsigned(read_3bytes(data)?.into())),
        DW_FORM_str4 => Some(AttrValue::Unsigned(data.read_u32()?.into())),
        DW_FORM_addrx1 => Some(AttrValue::Unsigned(data.read_u8()?.into())),
        DW_FORM_addrx2 => Some(AttrValue::Unsigned(data.read_u16()?.into())),
        DW_FORM_addrx3 => Some(AttrValue::Unsigned(read_3bytes(data)?.into())),
        DW_FORM_addrx4 => Some(AttrValue::Unsigned(data.read_u32()?.into())),
        _ => None,
    }
}

/// Extract the value of an attribute from a data buffer.
///
/// This function works with [`parse_abbrev_attr()`], that parse the
/// attribute specifications of DIEs delcared in the abbreviation
/// table in the .debug_abbrev section, by using the result of
/// [`parse_abbrev_attr()`] to parse the value of an attribute of a
/// DIE.
///
/// # Arguments
///
/// * `data` - A buffer where the value is in.
/// * `form` - The format of the value. (DW_FORM_*)
/// * `dwarf_sz` - Describe the DWARF format. (4 for 32-bits and 8 for 64-bits)
/// * `addr_sz` - The size of an address of the target platform. (4 for 32-bits and 8 for 64-bits)
///
/// Return AttrValue and the number of bytes it takes.
fn extract_attr_value(
    mut data: &[u8],
    form: u8,
    dwarf_sz: usize,
    addr_sz: usize,
) -> Option<(AttrValue<'_>, usize)> {
    let data = &mut data;
    let before = (*data).as_ptr();
    let value = extract_attr_value_impl(data, form, dwarf_sz, addr_sz)?;
    let after = (*data).as_ptr();
    // TODO: Remove this workaround once callers no longer require an explicit
    //       byte count being passed out.
    // SAFETY: Both pointers point into the same underlying byte array.
    let count = unsafe { after.offset_from(before) };
    Some((value, count.try_into().unwrap()))
}

/// Parse all abbreviations of an abbreviation table for a compile
/// unit.
///
/// An abbreviation table is usually for a compile unit, but not always.
///
/// Return a list of abbreviations and the number of bytes they take.
fn parse_cu_abbrevs(data: &[u8]) -> Option<(Vec<Abbrev>, usize)> {
    let mut pos = 0;
    let mut abbrevs = Vec::<Abbrev>::with_capacity(data.len() / 50); // Heuristic!

    while pos < data.len() {
        let (abbrev, bytes) = parse_abbrev(&data[pos..])?;
        pos += bytes;
        if abbrev.abbrev_code == 0x0 {
            return Some((abbrevs, pos));
        }
        abbrevs.push(abbrev);
    }
    None
}

/// Parse an Unit Header from a buffer.
///
/// An Unit Header is the header of a compile unit, at leat for v4.
///
/// # Arguments
///
/// * `data` - is the data from the `.debug_info` section.
fn parse_unit_header(data: &[u8]) -> Option<UnitHeader> {
    if data.len() < 4 {
        return None;
    }

    let mut pos = 0;
    let mut init_length = decode_uword(data) as usize;
    pos += 4;

    let bits64 = init_length == 0xffffffff;
    if bits64 {
        if (pos + 8) > data.len() {
            return None;
        }
        init_length = decode_udword(&data[pos..]) as usize;
        pos += 8;
    }

    if (pos + 2) > data.len() {
        return None;
    }
    let version = decode_uhalf(&data[pos..]);
    pos += 2;

    if version == 0x4 {
        let debug_abbrev_offset: u64 = if bits64 {
            if (pos + 8) > data.len() {
                return None;
            }
            let v = decode_udword(&data[pos..]);
            pos += 8;
            v
        } else {
            if (pos + 4) > data.len() {
                return None;
            }
            let v = decode_uword(&data[pos..]);
            pos += 4;
            v as u64
        };
        let address_size = data[pos];
        pos += 1;
        return Some(UnitHeader::CompileV4(CUHeaderV4 {
            init_length,
            bits64,
            version,
            debug_abbrev_offset,
            address_size,
            hdr_size: pos,
        }));
    }

    if (pos + 1) > data.len() {
        return None;
    }
    let unit_type = data[pos];
    pos += 1;

    match unit_type {
        DW_UT_compile => {
            if (pos + 1) > data.len() {
                return None;
            }
            let address_size = data[pos];
            pos += 1;

            let debug_abbrev_offset: u64 = if bits64 {
                if (pos + 8) > data.len() {
                    return None;
                }
                let v = decode_udword(&data[pos..]);
                pos += 8;
                v
            } else {
                if (pos + 4) > data.len() {
                    return None;
                }
                let v = decode_uword(&data[pos..]);
                pos += 4;
                v as u64
            };
            Some(UnitHeader::CompileV5(CUHeaderV5 {
                init_length,
                bits64,
                version,
                unit_type,
                address_size,
                debug_abbrev_offset,
                hdr_size: pos,
            }))
        }
        _ => Some(UnitHeader::Unknown(UnknownHeader {
            init_length,
            bits64,
            version,
            unit_type,
            hdr_size: pos,
        })),
    }
}

/// Debug Information Entry.
///
/// A DIE starts with the code of its abbreviation followed by the
/// attribute values described by the abbreviation.  The code of an
/// abbreviation is an index to the abbreviation table of the compile
/// unit.
#[allow(clippy::upper_case_acronyms)]
pub struct DIE<'a> {
    pub tag: u8,
    pub abbrev: Option<&'a Abbrev>,
    abbrev_attrs: &'a [AbbrevAttr],
    abbrev_attrs_idx: usize,
    data: &'a [u8],
    dieiter: &'a mut DIEIter<'a>,
    reading_offset: usize,
    done: bool,
}

impl<'a> DIE<'a> {
    #[inline]
    pub fn exhaust(&mut self) -> Result<(), Error> {
        let abbrev_attrs = self.abbrev_attrs;

        if self.done {
            return Ok(());
        }

        while self.abbrev_attrs_idx < abbrev_attrs.len() {
            let attr = &abbrev_attrs[self.abbrev_attrs_idx];
            self.abbrev_attrs_idx += 1;

            if attr.form == 0 {
                continue;
            }
            let (_value, bytes) = extract_attr_value(
                &self.data[self.reading_offset..],
                attr.form,
                self.dieiter.dwarf_sz,
                self.dieiter.addr_sz,
            )
            .ok_or_else(|| {
                Error::new(ErrorKind::InvalidData, "failed to parse attribute values")
            })?;
            self.reading_offset += bytes;
        }
        self.dieiter.die_finish_reading(self.reading_offset);
        self.done = true;
        Ok(())
    }
}

impl<'a> Iterator for DIE<'a> {
    // name, form, opt, value
    type Item = (u8, u8, u128, AttrValue<'a>);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        self.abbrev?;

        if self.abbrev_attrs_idx < self.abbrev_attrs.len() {
            let AbbrevAttr { name, form, opt } = self.abbrev_attrs[self.abbrev_attrs_idx];
            self.abbrev_attrs_idx += 1;

            #[cfg(debug)]
            if form == 0 {
                assert_eq!(self.abbrev_off, abbrev.attrs.len());
            }
            if form == 0 {
                self.dieiter.die_finish_reading(self.reading_offset);
                self.done = true;
                return None;
            }

            let (value, bytes) = extract_attr_value(
                &self.data[self.reading_offset..],
                form,
                self.dieiter.dwarf_sz,
                self.dieiter.addr_sz,
            )?;
            self.reading_offset += bytes;
            Some((name, form, opt, value))
        } else {
            self.dieiter.die_finish_reading(self.reading_offset);
            self.done = true;
            None
        }
    }
}

/// The iterator of DIEs in an Unit.
pub struct DIEIter<'a> {
    data: &'a [u8],
    dwarf_sz: usize,
    addr_sz: usize,
    off: usize,
    off_delta: usize,
    cur_depth: usize,
    abbrevs: Vec<Abbrev>,
    abbrev: Option<&'a Abbrev>,
    die_reading_done: bool,
    done: bool,
}

impl<'a> DIEIter<'a> {
    pub fn die_finish_reading(&mut self, size: usize) {
        self.die_reading_done = true;
        self.off += size;
    }

    pub fn seek_to_sibling(&mut self, off: usize) {
        self.off = off - self.off_delta;
        self.cur_depth -= 1;
        self.die_reading_done = true;
    }

    #[inline]
    pub fn exhaust_die(&mut self) -> Result<(), Error> {
        assert!(
            !self.die_reading_done,
            "DIE should not have been exhausted!"
        );
        let abbrev = self.abbrev.unwrap();
        for attr in abbrev.all_attrs() {
            if attr.form == 0 {
                continue;
            }
            let (_value, bytes) = extract_attr_value(
                &self.data[self.off..],
                attr.form,
                self.dwarf_sz,
                self.addr_sz,
            )
            .ok_or_else(|| {
                Error::new(ErrorKind::InvalidData, "failed to parse attribute values")
            })?;
            self.off += bytes;
        }
        self.die_reading_done = true;
        Ok(())
    }
}

impl<'a> Iterator for DIEIter<'a> {
    type Item = DIE<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.die_reading_done {
            self.exhaust_die().unwrap();
        }
        if self.done {
            return None;
        }

        let (abbrev_idx, bytes) = decode_leb128_128(&self.data[self.off..])?;
        self.off += bytes as usize;

        if abbrev_idx == 0 {
            self.cur_depth -= 1;
            if self.cur_depth == 0 {
                self.done = true;
            }
            Some(DIE {
                tag: 0,
                abbrev: None,
                abbrev_attrs: &[],
                abbrev_attrs_idx: 0,
                data: &self.data[self.off..],
                dieiter: unsafe { mem::transmute(self) },
                reading_offset: 0,
                done: false,
            })
        } else {
            let abbrev = unsafe { mem::transmute(&self.abbrevs[abbrev_idx as usize - 1]) };
            self.abbrev = Some(abbrev);
            if abbrev.has_children {
                self.cur_depth += 1;
            }

            self.die_reading_done = false;
            Some(DIE {
                tag: abbrev.tag,
                abbrev: Some(abbrev),
                abbrev_attrs: abbrev.all_attrs(),
                abbrev_attrs_idx: 0,
                data: &self.data[self.off..],
                dieiter: unsafe { mem::transmute(self) },
                reading_offset: 0,
                done: false,
            })
        }
    }
}

/// An iterator of Units in the `.debug_info` section.
///
/// An iterator is built from the content of `.debug_info` section,
/// which is a list of compile units.  A compile unit usually refers
/// to a source file.  In the compile units, it is a forest of DIEs,
/// which presents functions, variables and other debug information.
pub struct UnitIter<'a> {
    info_data: &'a [u8],
    abbrev_data: &'a [u8],
    off: usize,
}

impl<'a> UnitIter<'a> {
    /// Build an iterator from the content of `.debug_info` & `.debug_abbrev`.
    ///
    /// # Arguments
    ///
    /// * `info_data` is the content of the `.debug_info` section.
    /// * `abbrev_data` is the content of the `.debug_abbrev` section.
    pub fn new(info_data: &'a [u8], abbrev_data: &'a [u8]) -> UnitIter<'a> {
        UnitIter {
            info_data,
            abbrev_data,
            off: 0,
        }
    }
}

impl<'a> Iterator for UnitIter<'a> {
    type Item = (UnitHeader, DIEIter<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        let off = self.off;
        let uh = parse_unit_header(&self.info_data[off..])?;
        let hdr_sz = uh.header_size();
        self.off += uh.unit_size();

        match uh {
            UnitHeader::CompileV4(ref cuh) => {
                let dwarf_sz = if cuh.bits64 { 8 } else { 4 };
                let addr_sz = cuh.address_size as usize;
                let (abbrevs, _) =
                    parse_cu_abbrevs(&self.abbrev_data[cuh.debug_abbrev_offset as usize..])?;
                Some((
                    uh,
                    DIEIter {
                        data: &self.info_data[off + hdr_sz..],
                        dwarf_sz,
                        addr_sz,
                        off: 0,
                        off_delta: hdr_sz,
                        cur_depth: 0,
                        abbrevs,
                        abbrev: None,
                        die_reading_done: true,
                        done: false,
                    },
                ))
            }
            UnitHeader::CompileV5(ref _cuh) => {
                todo!(); // BlazeSym supports only v4 so far.
            }
            _ => self.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::ElfParser;
    use std::env;
    use std::path::Path;

    #[test]
    fn test_parse_abbrev() {
        let raw = [
            0x01, 0x11, 0x01, 0x25, 0x0e, 0x13, 0x05, 0x03, 0x0e, 0x10, 0x17, 0x1b, 0x0e, 0xb4,
            0x42, 0x19, 0x11, 0x01, 0x55, 0x17, 0x00, 0x00, 0x02, 0x39, 0x01, 0x03, 0x0e, 0x00,
            0x00, 0x03, 0x04, 0x01, 0x49, 0x13, 0x6d, 0x19, 0x03, 0x0e, 0x0b, 0x0b, 0x88, 0x01,
            0x0f, 0x00, 0x00, 0x04, 0x28, 0x00, 0x03, 0x0e, 0x1c, 0x0f, 0x00, 0x00, 0x05, 0x13,
            0x01, 0x03, 0x0e, 0x0b, 0x0b, 0x88, 0x01, 0x0f, 0x00, 0x00,
        ];
        let (abbrev, bytes) = parse_abbrev(&raw).unwrap();
        assert_eq!(bytes, 22);
        assert_eq!(abbrev.abbrev_code, 0x1);
        assert_eq!(abbrev.tag, DW_TAG_compile_unit);
        assert!(abbrev.has_children);
        let mut pos = bytes;

        let (abbrev, bytes) = parse_abbrev(&raw[pos..]).unwrap();
        assert_eq!(bytes, 7);
        assert_eq!(abbrev.abbrev_code, 0x2);
        assert_eq!(abbrev.tag, DW_TAG_namespace);
        assert!(abbrev.has_children);
        pos += bytes;

        let (abbrev, bytes) = parse_abbrev(&raw[pos..]).unwrap();
        assert_eq!(bytes, 16);
        assert_eq!(abbrev.abbrev_code, 0x3);
        assert_eq!(abbrev.tag, DW_TAG_enumeration_type);
        assert!(abbrev.has_children);
        pos += bytes;

        let (abbrev, bytes) = parse_abbrev(&raw[pos..]).unwrap();
        assert_eq!(bytes, 9);
        assert_eq!(abbrev.abbrev_code, 0x4);
        assert!(!abbrev.has_children);
        pos += bytes;

        let (abbrev, bytes) = parse_abbrev(&raw[pos..]).unwrap();
        assert_eq!(bytes, 12);
        assert_eq!(abbrev.abbrev_code, 0x5);
        assert!(abbrev.has_children);
    }

    #[test]
    fn test_parse_cu_abbrevs() {
        let raw = [
            0x01, 0x11, 0x01, 0x25, 0x0e, 0x13, 0x05, 0x03, 0x0e, 0x10, 0x17, 0x1b, 0x0e, 0xb4,
            0x42, 0x19, 0x11, 0x01, 0x55, 0x17, 0x00, 0x00, 0x02, 0x39, 0x01, 0x03, 0x0e, 0x00,
            0x00, 0x03, 0x04, 0x01, 0x49, 0x13, 0x6d, 0x19, 0x03, 0x0e, 0x0b, 0x0b, 0x88, 0x01,
            0x0f, 0x00, 0x00, 0x04, 0x28, 0x00, 0x03, 0x0e, 0x1c, 0x0f, 0x00, 0x00, 0x05, 0x13,
            0x01, 0x03, 0x0e, 0x0b, 0x0b, 0x88, 0x01, 0x0f, 0x00, 0x00, 0x00,
        ];
        let (abbrevs, bytes) = parse_cu_abbrevs(&raw).unwrap();
        assert_eq!(abbrevs.len(), 0x5);
        assert_eq!(bytes, raw.len());
    }

    #[test]
    fn test_unititer() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("dwarf-example");
        let elfparser = ElfParser::open(&bin_name).unwrap();
        let abbrev_idx = elfparser.find_section(".debug_abbrev").unwrap();
        let abbrev = elfparser.read_section_raw(abbrev_idx).unwrap();
        let info_idx = elfparser.find_section(".debug_info").unwrap();
        let info = elfparser.read_section_raw(info_idx).unwrap();

        let iter = UnitIter::new(&info, &abbrev);
        let mut cnt = 0;
        let mut die_cnt = 0;
        let mut attr_cnt = 0;
        let mut subprog_cnt = 0;
        for (_uh, dieiter) in iter {
            cnt += 1;
            for die in dieiter {
                die_cnt += 1;
                if die.tag == DW_TAG_subprogram {
                    subprog_cnt += 1;
                }
                for (_name, _form, _opt, _value) in die {
                    attr_cnt += 1;
                }
            }
        }
        assert_eq!(cnt, 9);
        assert_eq!(die_cnt, 78752);
        assert_eq!(subprog_cnt, 12451);
        assert_eq!(attr_cnt, 275310);
    }
}
