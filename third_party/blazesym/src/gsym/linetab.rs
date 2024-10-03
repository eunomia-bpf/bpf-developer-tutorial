//! Opcode runner of GSYM line table.

use crate::util::decode_leb128;
use crate::util::decode_leb128_s;

/// End of the line table
const END_SEQUENCE: u8 = 0x00;
/// Set [`LineTableRow.file_idx`], don't push a row.
const SET_FILE: u8 = 0x01;
/// Increment [`LineTableRow.address`], and push a row.
const ADVANCE_PC: u8 = 0x02;
/// Set [`LineTableRow.file_line`], don't push a row.
const ADVANCE_LINE: u8 = 0x03;
/// All special opcodes push a row.
const FIRST_SPECIAL: u8 = 0x04;


#[derive(Debug)]
pub enum RunResult {
    /// Run the operator successfully.
    Ok(usize),
    /// This operator creates a new row.
    NewRow(usize),
    /// The end of the program (the operator stream.)
    End,
    /// Fails to run the operator at the position.
    Err,
}

#[derive(Debug)]
pub struct LineTableHeader {
    /// `min_data` & `max_delta` together is used to set the range and encoding
    /// of line delta in special operator. Line delta is the number of lines
    /// that a line table row is different from the previous row.
    pub min_delta: i64,
    pub max_delta: i64,
    pub first_line: u32,
}

#[derive(Clone, Debug)]
pub struct LineTableRow {
    pub address: u64,
    pub file_idx: u32,
    pub file_line: u32,
}

impl LineTableRow {
    /// Create a `LineTableRow` to use as the states of a line table virtual
    /// machine.
    ///
    /// The returned `LineTableRow` can be passed to [`run_op`] as `ctx`.
    ///
    /// # Arguments
    ///
    /// * `header` - is a [`LineTableHeader`] returned by [`parse_line_table_header()`].
    /// * `symaddr` - the address of the symbol that `header` belongs to.
    pub fn line_table_row_from(header: &LineTableHeader, symaddr: u64) -> LineTableRow {
        Self {
            address: symaddr,
            file_idx: 1,
            file_line: header.first_line,
        }
    }
}


/// Run a GSYM line table operator/instruction in the buffer.
///
/// # Arguments
///
/// * `ctx` - a line table row to present the current states of the virtual
///           machine. [`line_table_row_from()`] can create a `LineTableRow` to
///           keep the states of a virtual machine.
/// * `header` - is a `LineTableHeader`.
/// * `ops` - is the buffer of the operators following the `LineTableHeader` in
///           a GSYM file.
/// * `pc` - is the program counter of the virtual machine.
///
/// Returns a [`RunResult`]. `Ok` and `NewRow` will return the size of this
/// instruction. The caller should adjust the value of `pc` according to the
/// value returned.
pub fn run_op(
    ctx: &mut LineTableRow,
    header: &LineTableHeader,
    ops: &[u8],
    pc: usize,
) -> RunResult {
    let mut off = pc;
    let op = ops[off];
    off += 1;
    match op {
        END_SEQUENCE => RunResult::End,
        SET_FILE => {
            if let Some((f, bytes)) = decode_leb128(&ops[off..]) {
                off += bytes as usize;
                ctx.file_idx = f as u32;
                RunResult::Ok(off - pc)
            } else {
                RunResult::Err
            }
        }
        ADVANCE_PC => {
            if let Some((adv, bytes)) = decode_leb128(&ops[off..]) {
                off += bytes as usize;
                ctx.address += adv;
                RunResult::NewRow(off - pc)
            } else {
                RunResult::Err
            }
        }
        ADVANCE_LINE => {
            if let Some((adv, bytes)) = decode_leb128_s(&ops[off..]) {
                off += bytes as usize;
                ctx.file_line = (ctx.file_line as i64 + adv) as u32;
                RunResult::Ok(off - pc)
            } else {
                RunResult::Err
            }
        }
        // Special operators.
        //
        // All operators that have a value greater than or equal to
        // FIRST_SPECIAL are considered special operators. These operators
        // change both the line number and address of the virtual machine and
        // emit a new row.
        _ => {
            let adjusted = (op - FIRST_SPECIAL) as i64;
            // The range of line number delta is from min_delta to max_delta,
            // including max_delta.
            let range = header.max_delta - header.min_delta + 1;
            if range == 0 {
                return RunResult::Err;
            }
            let line_delta = header.min_delta + (adjusted % range);
            let addr_delta = adjusted / range;

            let file_line = ctx.file_line as i32 + line_delta as i32;
            if file_line < 1 {
                return RunResult::Err;
            }

            ctx.file_line = file_line as u32;
            ctx.address = (ctx.address as i64 + addr_delta) as u64;
            RunResult::NewRow(off - pc)
        }
    }
}
