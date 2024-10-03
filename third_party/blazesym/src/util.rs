use std::ffi::CStr;
use std::fs;
use std::io::{BufRead, BufReader, Error, ErrorKind};
use std::mem::size_of;
use std::path::PathBuf;

use regex::Regex;

pub fn search_address_key<T, V: Ord>(
    data: &[T],
    address: V,
    keyfn: &dyn Fn(&T) -> V,
) -> Option<usize> {
    let mut left = 0;
    let mut right = data.len();

    if right == 0 {
        return None;
    }
    if address < keyfn(&data[0]) {
        return None;
    }

    while (left + 1) < right {
        let v = (left + right) / 2;
        let key = keyfn(&data[v]);

        if key == address {
            return Some(v);
        }
        if address < key {
            right = v;
        } else {
            left = v;
        }
    }

    Some(left)
}

/// Do binary search but skip entries not having a key.
pub fn search_address_opt_key<T, V: Ord>(
    data: &[T],
    address: V,
    keyfn: &dyn Fn(&T) -> Option<V>,
) -> Option<usize> {
    let mut left = 0;
    let mut right = data.len();

    while left < right {
        let left_key = keyfn(&data[left]);
        if left_key.is_some() {
            break;
        }
        left += 1;
    }

    if left == right {
        return None;
    }

    if address < keyfn(&data[left]).unwrap() {
        return None;
    }

    while (left + 1) < right {
        let mut v = (left + right) / 2;

        let v_saved = v;
        // Skip entries not having a key
        while v < right {
            let key = keyfn(&data[v]);
            if key.is_some() {
                break;
            }
            v += 1;
        }
        // All entries at the right side haven't keys.
        // Shrink to the left side.
        if v == right {
            right = v_saved;
            continue;
        }

        let key = keyfn(&data[v]).unwrap();

        if key == address {
            return Some(v);
        }
        if address < key {
            right = v;
        } else {
            left = v;
        }
    }

    Some(left)
}

pub fn extract_string(raw: &[u8], off: usize) -> Option<&str> {
    let mut end = off;

    if off >= raw.len() {
        return None;
    }
    while end < raw.len() && raw[end] != 0 {
        end += 1;
    }
    if end >= raw.len() {
        return None;
    }
    CStr::from_bytes_with_nul(&raw[off..=end])
        .ok()?
        .to_str()
        .ok()
}

pub struct LinuxMapsEntry {
    pub loaded_address: u64,
    pub end_address: u64,
    pub mode: u8,
    pub offset: u64,
    pub path: PathBuf,
}

pub fn parse_maps(pid: u32) -> Result<Vec<LinuxMapsEntry>, Error> {
    let mut entries = Vec::<LinuxMapsEntry>::new();
    let file_name = if pid == 0 {
        String::from("/proc/self/maps")
    } else {
        format!("/proc/{pid}/maps")
    };
    let file = fs::File::open(file_name)?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let re_ptn = Regex::new(
        r"^([0-9a-f]+)-([0-9a-f]+) ([rwxp\\-]+) ([0-9a-f]+) [0-9a-f]+:[0-9a-f]+ [0-9]+ *((/[^/]+)+)$",
    );
    if re_ptn.is_err() {
        println!("{re_ptn:?}");
        return Err(Error::new(ErrorKind::InvalidData, "Failed to build regex"));
    }
    let re_ptn = re_ptn.unwrap();

    while reader.read_line(&mut line)? > 0 {
        if let Some(caps) = re_ptn.captures(&line) {
            let loaded_address_str = caps.get(1).unwrap().as_str();
            let loaded_address = u64::from_str_radix(loaded_address_str, 16).unwrap();

            let end_address_str = caps.get(2).unwrap().as_str();
            let end_address = u64::from_str_radix(end_address_str, 16).unwrap();

            let mode_str = caps.get(3).unwrap().as_str();
            let mut mode = 0;
            for c in mode_str.chars() {
                mode = (mode << 1) | u8::from(c != '-');
            }

            let offset = u64::from_str_radix(caps.get(4).unwrap().as_str(), 16).unwrap();
            let path = caps.get(5).unwrap().as_str().strip_suffix('\n').unwrap();
            let mut path_str = path.to_string();
            if let Some(pos) = path.rfind(" (deleted)") {
                if pos == path.len() - " (deleted)".len() {
                    path_str = format!("/proc/{pid}/map_files/{loaded_address:x}-{end_address:x}");
                }
            }

            let entry = LinuxMapsEntry {
                loaded_address,
                end_address,
                mode,
                offset,
                path: PathBuf::from(path_str),
            };
            entries.push(entry);
        }
        line.clear();
    }

    Ok(entries)
}

#[inline]
pub fn decode_leb128_128(mut data: &[u8]) -> Option<(u128, u8)> {
    data.read_u128_leb128()
}

#[inline]
pub fn decode_leb128(mut data: &[u8]) -> Option<(u64, u8)> {
    data.read_u128_leb128().map(|(v, s)| (v as u64, s))
}

#[inline]
pub fn decode_leb128_s(mut data: &[u8]) -> Option<(i64, u8)> {
    data.read_i128_leb128().map(|(v, s)| (v as i64, s))
}

#[inline]
pub fn decode_uhalf(mut data: &[u8]) -> u16 {
    // TODO: Need to handle errors more gracefully.
    data.read_u16().unwrap()
}

#[inline]
pub fn decode_uword(mut data: &[u8]) -> u32 {
    // TODO: Need to handle errors more gracefully.
    data.read_u32().unwrap()
}

#[inline]
pub fn decode_udword(mut data: &[u8]) -> u64 {
    // TODO: Need to handle errors more gracefully.
    data.read_u64().unwrap()
}

mod sealed {
    /// A marker trait for "plain old data" data types.
    ///
    /// # Safety
    /// Only safe to implement for types that are valid for any bit pattern.
    pub unsafe trait Pod {}

    unsafe impl Pod for i8 {}
    unsafe impl Pod for u8 {}
    unsafe impl Pod for i16 {}
    unsafe impl Pod for u16 {}
    unsafe impl Pod for i32 {}
    unsafe impl Pod for u32 {}
    unsafe impl Pod for i64 {}
    unsafe impl Pod for u64 {}
    unsafe impl Pod for i128 {}
    unsafe impl Pod for u128 {}
}

/// An trait providing utility functions for reading data from a byte buffer.
pub trait ReadRaw<'data> {
    /// Ensure that `len` bytes are available for consumption.
    fn ensure(&self, len: usize) -> Option<()>;

    /// Consume and return `len` bytes.
    fn read_slice(&mut self, len: usize) -> Option<&'data [u8]>;

    /// Read a NUL terminated string.
    fn read_cstr(&mut self) -> Option<&'data CStr>;

    /// Read anything implementing `Pod`.
    #[inline]
    fn read_pod<T>(&mut self) -> Option<T>
    where
        T: sealed::Pod,
    {
        let data = self.read_slice(size_of::<T>())?;
        // SAFETY: `T` is `Pod` and hence valid for any bit pattern. The pointer
        //         is guaranteed to be valid and to point to memory of at least
        //         `sizeof(T)` bytes.
        let value = unsafe { data.as_ptr().cast::<T>().read_unaligned() };
        Some(value)
    }

    /// Read a `u8` value.
    #[inline]
    fn read_u8(&mut self) -> Option<u8> {
        self.read_pod::<u8>()
    }

    /// Read a `i16` value.
    #[inline]
    fn read_i16(&mut self) -> Option<i16> {
        self.read_pod::<i16>()
    }

    /// Read a `u16` value.
    #[inline]
    fn read_u16(&mut self) -> Option<u16> {
        self.read_pod::<u16>()
    }

    /// Read a `i32` value.
    #[inline]
    fn read_i32(&mut self) -> Option<i32> {
        self.read_pod::<i32>()
    }

    /// Read a `u32` value.
    #[inline]
    fn read_u32(&mut self) -> Option<u32> {
        self.read_pod::<u32>()
    }

    /// Read a `u64` value.
    #[inline]
    fn read_u64(&mut self) -> Option<u64> {
        self.read_pod::<u64>()
    }

    /// Read a `u128` encoded as unsigned variable length little endian base 128
    /// value.
    ///
    /// The function returns the value read along with the number of bytes
    /// consumed.
    fn read_u128_leb128(&mut self) -> Option<(u128, u8)> {
        let mut shift = 0;
        let mut value = 0u128;
        while let Some(bytes) = self.read_slice(1) {
            if let [byte] = bytes {
                value |= ((byte & 0b0111_1111) as u128) << shift;
                shift += 7;
                if (byte & 0b1000_0000) == 0 {
                    return Some((value, shift / 7));
                }
            } else {
                unreachable!()
            }
        }
        None
    }

    /// Read a `u128` encoded as signed variable length little endian base 128
    /// value.
    ///
    /// The function returns the value read along with the number of bytes
    /// consumed.
    fn read_i128_leb128(&mut self) -> Option<(i128, u8)> {
        let (value, shift) = self.read_u128_leb128()?;
        let sign_bits = 128 - shift * 7;
        let value = ((value as i128) << sign_bits) >> sign_bits;
        Some((value, shift))
    }
}

impl<'data> ReadRaw<'data> for &'data [u8] {
    #[inline]
    fn ensure(&self, len: usize) -> Option<()> {
        if len > self.len() {
            return None;
        }
        Some(())
    }

    #[inline]
    fn read_slice(&mut self, len: usize) -> Option<&'data [u8]> {
        self.ensure(len)?;
        let (a, b) = self.split_at(len);
        *self = b;
        Some(a)
    }

    #[inline]
    fn read_cstr(&mut self) -> Option<&'data CStr> {
        let idx = self.iter().position(|byte| *byte == b'\0')?;
        CStr::from_bytes_with_nul(self.read_slice(idx + 1)?).ok()
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Make sure that `[u8]::ensure` works as expected.
    #[test]
    fn u8_slice_len_ensurance() {
        let slice = [0u8; 0].as_slice();
        assert_eq!(slice.ensure(0), Some(()));
        assert_eq!(slice.ensure(1), None);

        let slice = [1u8].as_slice();
        assert_eq!(slice.ensure(0), Some(()));
        assert_eq!(slice.ensure(1), Some(()));
        assert_eq!(slice.ensure(2), None);
    }

    /// Check that we can read various integers from a slice.
    #[test]
    fn pod_reading() {
        macro_rules! test {
            ($type:ty) => {{
                let max = <$type>::MAX.to_ne_bytes();
                let one = (1 as $type).to_ne_bytes();

                let mut data = Vec::new();
                let () = data.extend_from_slice(&max);
                let () = data.extend_from_slice(&one);
                let () = data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

                let mut raw = data.as_slice();
                let uword = raw.read_pod::<$type>().unwrap();
                assert_eq!(uword, <$type>::MAX);

                let uword = raw.read_pod::<$type>().unwrap();
                assert_eq!(uword, 1);
            }};
        }

        test!(i8);
        test!(u8);
        test!(i16);
        test!(u16);
        test!(i32);
        test!(u32);
        test!(i64);
        test!(u64);
        test!(i128);
        test!(u128);
    }

    /// Test reading of signed and unsigned 16 and 32 bit values against known
    /// results.
    #[test]
    fn word_reading() {
        let data = 0xf936857fu32.to_ne_bytes();
        assert_eq!(data.as_slice().read_u16().unwrap(), 0x857f);
        assert_eq!(data.as_slice().read_i16().unwrap(), -31361);
        assert_eq!(data.as_slice().read_u32().unwrap(), 0xf936857f);
        assert_eq!(data.as_slice().read_i32().unwrap(), -113867393);
    }

    /// Make sure that we can read leb128 encoded values.
    #[test]
    fn leb128_reading() {
        let data = [0xf4, 0xf3, 0x75];
        let (v, s) = data.as_slice().read_u128_leb128().unwrap();
        assert_eq!(v, 0x1d79f4);
        assert_eq!(s, 3);

        let (v, s) = data.as_slice().read_i128_leb128().unwrap();
        assert_eq!(v, -165388);
        assert_eq!(s, 3);
    }

    /// Check that we can read a NUL terminated string from a slice.
    #[test]
    fn cstr_reading() {
        let mut slice = b"abc\x001234".as_slice();

        let cstr = slice.read_cstr().unwrap();
        assert_eq!(cstr, CStr::from_bytes_with_nul(b"abc\0").unwrap());

        // No terminating NUL byte.
        let mut slice = b"abc".as_slice();
        assert_eq!(slice.read_cstr(), None);
    }
}
