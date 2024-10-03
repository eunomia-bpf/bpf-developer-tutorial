use std::fs::File;
use std::io::{Error, Read};
use std::mem;
use std::path::{Path, PathBuf};

use crate::{AddressLineInfo, FindAddrOpts, SymResolver, SymbolInfo};

use super::linetab::run_op;
use super::linetab::LineTableRow;
use super::linetab::RunResult;
use super::parser::find_address;
use super::parser::parse_address_data;
use super::parser::parse_line_table_header;
use super::parser::GsymContext;
use super::types::InfoTypeLineTableInfo;

/// The symbol resolver for the GSYM format.
pub struct GsymResolver {
    file_name: PathBuf,
    ctx: GsymContext<'static>,
    _data: Vec<u8>,
    loaded_address: u64,
}

impl GsymResolver {
    pub fn new(file_name: PathBuf, loaded_address: u64) -> Result<GsymResolver, Error> {
        let mut fo = File::open(&file_name)?;
        let mut data = vec![];
        fo.read_to_end(&mut data)?;
        let ctx = GsymContext::parse_header(&data)?;

        Ok(GsymResolver {
            file_name,
            // SAFETY: the lifetime of ctx depends on data, which is
            // owned by the object.  So, it is safe to strip the
            // lifetime of ctx.
            ctx: unsafe { mem::transmute(ctx) },
            _data: data,
            loaded_address,
        })
    }
}

impl SymResolver for GsymResolver {
    fn get_address_range(&self) -> (u64, u64) {
        let sz = self.ctx.num_addresses();
        if sz == 0 {
            return (0, 0);
        }

        // TODO: Must not unwrap.
        let start = self.ctx.addr_at(0).unwrap() + self.loaded_address;
        // TODO: Must not unwrap.
        let end = self.ctx.addr_at(sz - 1).unwrap()
            + self.ctx.addr_info(sz - 1).unwrap().size as u64
            + self.loaded_address;
        (start, end)
    }

    fn find_symbols(&self, addr: u64) -> Vec<(&str, u64)> {
        let addr = addr - self.loaded_address;
        let idx = if let Some(idx) = find_address(&self.ctx, addr) {
            idx
        } else {
            return vec![];
        };

        let found = if let Some(addr) = self.ctx.addr_at(idx) {
            addr
        } else {
            return vec![];
        };

        if addr < found {
            return vec![];
        }

        let info = if let Some(info) = self.ctx.addr_info(idx) {
            info
        } else {
            return Vec::new();
        };

        let name = if let Some(name) = self.ctx.get_str(info.name as usize) {
            name
        } else {
            return Vec::new();
        };

        vec![(name, found + self.loaded_address)]
    }

    fn find_address(&self, _name: &str, _opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        // It is inefficient to find the address of a symbol with
        // GSYM.  We may support it in the future if needed.
        None
    }

    fn find_address_regex(&self, _pattern: &str, _opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        None
    }

    /// Finds the source code location for a given address.
    ///
    /// This function takes in an address and returns the file path,
    /// line number and column of the line in the source code that
    /// the address corresponds to. If it doesn't find any match it
    /// returns `None`.
    ///
    /// # Arguments
    ///
    /// * `addr` - The address to find the source code location for.
    ///
    /// # Returns
    ///
    /// The `AddressLineInfo` corresponding to the address or `None`.
    fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo> {
        let addr = addr.checked_sub(self.loaded_address)?;
        let idx = find_address(&self.ctx, addr)?;
        let symaddr = self.ctx.addr_at(idx)?;
        if addr < symaddr {
            return None;
        }
        let addrinfo = self.ctx.addr_info(idx)?;
        if addr >= (symaddr + addrinfo.size as u64) {
            return None;
        }

        let addrdatas = parse_address_data(addrinfo.data);
        for adr_ent in addrdatas {
            if adr_ent.typ != InfoTypeLineTableInfo {
                continue;
            }
            // Continue to execute all GSYM line table operations
            // until the end of the buffer is reached or a row
            // containing addr is located.
            let (lntab_hdr, hdr_bytes) = parse_line_table_header(adr_ent.data)?;
            let ops = &adr_ent.data[hdr_bytes..];
            let mut lntab_row = LineTableRow::line_table_row_from(&lntab_hdr, symaddr);
            let mut last_lntab_row = lntab_row.clone();
            let mut row_cnt = 0;
            let mut pc = 0;
            while pc < ops.len() {
                match run_op(&mut lntab_row, &lntab_hdr, ops, pc) {
                    RunResult::Ok(bytes) => {
                        pc += bytes;
                    }
                    RunResult::NewRow(bytes) => {
                        pc += bytes;
                        row_cnt += 1;
                        if addr < lntab_row.address {
                            if row_cnt == 1 {
                                // The address is lower than the first row.
                                return None;
                            }
                            // Rollback to the last row.
                            lntab_row = last_lntab_row;
                            break;
                        }
                        last_lntab_row = lntab_row.clone();
                    }
                    RunResult::End | RunResult::Err => {
                        break;
                    }
                }
            }

            if row_cnt == 0 {
                continue;
            }

            let finfo = self.ctx.file_info(lntab_row.file_idx as usize)?;
            let dirname = self.ctx.get_str(finfo.directory as usize)?;
            let filename = self.ctx.get_str(finfo.filename as usize)?;
            let path = Path::new(dirname).join(filename).to_str()?.to_string();
            return Some(AddressLineInfo {
                path,
                line_no: lntab_row.file_line as usize,
                column: 0,
            });
        }
        None
    }

    fn addr_file_off(&self, _addr: u64) -> Option<u64> {
        // Unavailable
        None
    }

    fn get_obj_file_name(&self) -> &Path {
        &self.file_name
    }

    fn repr(&self) -> String {
        format!("GSYM {:?}", self.file_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;


    /// Make sure that we can find file line information for a function, if available.
    #[test]
    fn test_find_line_info() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.gsym");
        let resolver = GsymResolver::new(test_gsym, 0).unwrap();

        // `main` resides at address 0x2000000, and it's located at line 19.
        let info = resolver.find_line_info(0x2000000).unwrap();
        assert_eq!(info.line_no, 19);
        assert!(info.path.ends_with("test-gsym.c"));

        // `factorial` resides at address 0x2000100, and it's located at line 7.
        let info = resolver.find_line_info(0x2000100).unwrap();
        assert_eq!(info.line_no, 7);
        assert!(info.path.ends_with("test-gsym.c"));
    }
}
