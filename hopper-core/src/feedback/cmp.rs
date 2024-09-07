//! Compare feedback
//! including: cmp instructions, compare functions such as strcmp

use std::{cell::RefCell, cmp::Ordering, collections::HashMap, ffi::CStr, rc::Rc};

use super::*;
use crate::{runtime::*, utils};

thread_local! {
    // key: cmp_id, value: (count, is_variable)
    pub static CMP_STAT: RefCell<HashMap<u32, (usize, bool)>> = RefCell::new(HashMap::new());
}

/// Compare types
#[derive(Debug, PartialEq, Eq)]
pub enum CmpType {
    Instcmp = 1,
    Strcmp = 17,
    Strncmp = 18,
    Memcmp = 19,
    Ignore = 100,
}

#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct CmpOperation {
    /// first operand: 0
    pub operand1: u64,
    /// second operand: 8
    pub operand2: u64,
    /// ID of the instruction : 16
    pub id: u32,
    /// size of operand: 20
    pub size: u32,
    /// type of cmp: 24
    pub ty: u16,
    /// Invoke at which statement index: 26
    pub stmt_index: u16,
    /// State of the cmp: 28
    pub state: u32,
}

#[derive(Debug, Clone)]
pub struct CmpState {
    /// Id of this cmp
    pub id: u32,
    /// refer to cmp in program's cmp_list
    pub op: Rc<RefCell<CmpOperation>>,
    /// is left side the mutate op affect?
    pub affect_left: bool,
    /// has deterministic steps for cmp done?
    pub det: bool,
}

#[derive(Debug, Clone)]
pub struct CmpBuf {
    pub id: u32,
    pub offset: usize,
    pub buf: Vec<u8>,
    pub det: bool,
}

impl CmpOperation {
    /// Calculate a state for the cmp
    /// `==` : 0x04
    /// `>`  : 0x01
    /// `<`  : 0x02
    pub fn calculate_state(&self) -> u32 {
        if self.is_instcmp() {
            let operand1 = { self.operand1 };
            let operand2 = { self.operand2 };
            match operand1.cmp(&operand2) {
                Ordering::Greater => 0x01,
                Ordering::Less => 0x02,
                Ordering::Equal => 0x04,
            }
        } else {
            // ignore strcmp\memcmp..
            0
        }
    }

    /// are the oprands in the comparison eqaul or nbot
    pub fn is_equal(&self) -> bool {
        self.is_instcmp() && self.operand1 == self.operand2
    }

    /// Get the compare type
    pub fn get_type(&self) -> CmpType {
        match self.ty {
            1 => CmpType::Instcmp,
            17 => CmpType::Strcmp,
            18 => CmpType::Strncmp,
            19 => CmpType::Memcmp,
            _ => CmpType::Ignore,
        }
    }

    /// is a compare instruction or not
    pub fn is_instcmp(&self) -> bool {
        self.get_type() == CmpType::Instcmp
    }

    /// Merge state of cmp
    /// simply use `or` for states
    /// TODO: how to use these state
    pub fn merge_state(&mut self, other: &Self) {
        self.state |= other.calculate_state();
    }

    /// Check if cmp is solved
    /// `==` and `!=` : > 0x04
    /// `>` and `<`  : 0x03
    /// there is no `>=` or `<=` in asm level
    pub fn is_solved(&self) -> bool {
        self.state > 0x04 || self.state == 0x03
    }

    pub fn log_cmp(&self) {
        println!(
            "CMP id: {}, ty: {}, size: {}, stmt: {}, operands: {:?}, {:?}, state: {:#04x}",
            { self.id },
            { self.ty },
            { self.size },
            { self.stmt_index },
            { self.operand1 },
            { self.operand2 },
            { self.state }
        );
    }
}

impl ShmIteratorItem for CmpOperation {
    fn check(&self) -> bool {
        self.stmt_index < 0xFFFF
    }
    fn get_key(&self) -> u32 {
        self.id
    }
}

impl InstrList {
    /// Convert to list of cmps that wrapped by Rc/RefCell
    /// Only track inst cmp
    pub fn get_cmp_ref_list(&self) -> Vec<Rc<RefCell<CmpOperation>>> {
        crate::log!(trace, "cmp_len: {}", self.cmp_len());
        self.cmp_iter(Some(crate::config::CMP_MAX_COUNTER))
            .filter_map(|c| {
                if !c.is_instcmp() {
                    return None;
                }
                let mut c = *c;
                c.state = c.calculate_state();
                // only get the first N
                CMP_STAT.with(|s| {
                    s.borrow_mut()
                        .entry(c.id)
                        .and_modify(|v| v.0 += 1)
                        .or_insert((1, false));
                });
                Some(Rc::new(RefCell::new(c)))
            })
            .collect()
    }

    pub fn get_cmp_ids(&self) -> Vec<u32> {
        self.cmp_iter(Some(8))
            .filter(|c| c.is_instcmp())
            .map(|c| c.id)
            .collect()
    }

    pub fn contain_cmp_chunks(&self, chunks: &[u32]) -> bool {
        let chunk_len = chunks.len();
        if chunk_len == 0 {
            return true;
        }
        let ids = self.get_cmp_ids();
        if ids.is_empty() || ids.len() < chunk_len {
            return false;
        }
        ids.windows(chunk_len).any(|w| w == chunks)
    }

    /// Can infer cmp instrutions or not
    /// Only single operation can be inferred
    fn can_associate_loc(program: &FuzzProgram) -> bool {
        if program.ops.len() == 1 {
            let op = &program.ops[0];
            if !op.key.is_null() && op.op.is_arithmetical() {
                return true;
            }
        }
        false
    }

    /// Associate location (mutation operator) with cmps
    pub fn associate_loc_with_cmp_instructions(
        &mut self,
        program: &FuzzProgram,
    ) -> eyre::Result<()> {
        crate::log_trace!("start infer cmp..");
        let can_associate = Self::can_associate_loc(program);
        // Now we disablel diff cmp if the mutation is complex.
        if !can_associate {
            return Ok(());
        }
        let cmp_diff = self.diff_cmp_operands(program, can_associate);
        if !can_associate || cmp_diff.is_empty() {
            return Ok(());
        }
        let op = &program.ops[0];
        if let Ok(is) = program.get_stmt_by_loc(&op.key) {
            match &is.stmt {
                FuzzStmt::Load(load) => {
                    crate::log!(trace, "try infer cmp instruction at : {:?}", op.key);
                    if let Ok(state) = load.state.get_child_by_fields(op.key.fields.as_slice()) {
                        // avoid add too many cmp to state
                        if (state.mutate.borrow()).related_cmps.len() > 25 {
                            return Ok(());
                        }
                        for cmp in cmp_diff {
                            crate::log!(
                                trace,
                                "loc <{}>{} affects cmp {:?}",
                                is.index.get(),
                                state.get_location_fields().serialize()?,
                                &cmp
                            );
                            // TODO: if it is a byte and not the start?
                            // crate::log!(info, "try add {cmp:?} for {:?}", op.key);
                            state.mutate.borrow_mut().affect_cmp(cmp);
                        }
                    }
                }
                FuzzStmt::Call(_call) => {
                    // ignore it
                }
                _ => {}
            }
        } else {
            eyre::bail!("get stmt by loc failed.");
        }
        Ok(())
    }

    /// Find differneces of cmp operands
    ///
    /// Use list to do strict compare.
    /// why not use map?? or skip match?
    fn diff_cmp_operands(&self, program: &FuzzProgram, can_associate: bool) -> Vec<CmpState> {
        let mut diff: Vec<CmpState> = vec![];
        let original = program.cmps.as_slice();
        crate::log!(
            trace,
            "cmp_len: {}, original_len: {}",
            self.cmp_len(),
            original.len()
        );
        for (cur_op, ori_op) in self
            .cmp_iter(Some(crate::config::CMP_MAX_COUNTER))
            .filter(|cmp| cmp.is_instcmp())
            .zip(original.iter())
        {
            // ignore function compare
            if !cur_op.is_instcmp() {
                continue;
            }
            let mut op = ori_op.borrow_mut();
            // crate::log!(trace, "cmp: {cur_op:?} vs {op:?}");
            if op.is_equal() {
                continue;
            }
            if cur_op.id != op.id {
                break;
            }
            let left_diff = op.operand1 != cur_op.operand1;
            let right_diff = op.operand2 != cur_op.operand2;
            if left_diff && right_diff {
                continue;
            }
            if left_diff || right_diff {
                // merge state
                op.merge_state(cur_op);
                // cmp is variable by input
                CMP_STAT.with(|s| {
                    s.borrow_mut()
                        .entry(cur_op.id)
                        .and_modify(|v| v.1 = true)
                        .or_insert((0, true));
                });
                if can_associate {
                    let state = CmpState {
                        id: cur_op.id,
                        op: ori_op.clone(),
                        affect_left: left_diff,
                        det: true,
                    };
                    diff.push(state)
                }
            }
        }
        crate::log!(trace, "find cmp diff : {diff:?}");
        diff
    }

    /// Find out locations that affect compare function: the pointer of locations is equals to
    /// the pointer used in compare functions.
    /// This function is invoked at executor/harness, so we should not compare it at fuzzer side.
    pub fn associate_loc_with_cmp_fn(
        &self,
        index: usize,
        stmts: &[IndexedStmt],
        resource_states: &ResourceStates,
    ) -> Vec<CmpRecord> {
        let mut cmp_fn_expectations = vec![];
        let index = index as u16;
        for c in self.cmp_iter(None) {
            if c.stmt_index != index {
                continue;
            }
            match c.get_type() {
                CmpType::Strcmp => {
                    let ret = find_cmp_fn_ptr_in_program(c, stmts, resource_states);
                    if let Some((loc, ptr)) = ret {
                        let buf = unsafe { CStr::from_ptr(ptr as *const i8) };
                        let mut buf = Vec::from(buf.to_bytes());
                        if let Some(last) = buf.last() {
                            if *last != 0_u8 {
                                buf.push(0);
                            }
                        }
                        crate::log_c!(trace, "field {:?} affect strcmp {:?}", loc, buf);
                        let rela = CmpRecord {
                            id: c.id,
                            loc,
                            buf,
                            call_index: { c.stmt_index } as usize,
                        };
                        cmp_fn_expectations.push(rela);
                    }
                }
                CmpType::Strncmp | CmpType::Memcmp => {
                    let ret = find_cmp_fn_ptr_in_program(c, stmts, resource_states);
                    if let Some((loc, ptr)) = ret {
                        let len = c.size as usize;
                        let buf = unsafe { std::slice::from_raw_parts(ptr, len) };
                        crate::log_c!(
                            trace,
                            "field {} affect strncmp/memcmp {:?}",
                            loc.serialize().unwrap(),
                            buf
                        );
                        let rela = CmpRecord {
                            id: c.id,
                            loc,
                            buf: buf.to_vec(),
                            call_index: { c.stmt_index } as usize,
                        };
                        cmp_fn_expectations.push(rela);
                    }
                }
                _ => {}
            }
        }
        crate::log_c!(trace, "finish associate cmp");
        cmp_fn_expectations
    }
}

/// Find pointer address used in compare function in the program
fn find_cmp_fn_ptr_in_program(
    cmp: &CmpOperation,
    stmts: &[IndexedStmt],
    resource_states: &ResourceStates,
) -> Option<(Location, *mut u8)> {
    let ptr1 = cmp.operand1 as *mut u8;
    let ptr2 = cmp.operand2 as *mut u8;
    let stmt_index = cmp.stmt_index as usize;
    if cmp.operand1 > 0 && utils::is_in_shlib(ptr2) {
        crate::log_c!(
            trace,
            "cmp function ptr1: {:?} before stmt: {}, state: {:#04x} ",
            ptr1,
            stmt_index,
            { cmp.state }
        );
        let ret = find_location_at_ptr(stmts, ptr1, resource_states);
        if let Some(loc) = ret {
            return Some((loc, ptr2));
        }
        // since the string may by copy to other memory adress, so we search it by its prefix.
        // FIXME: we assume it is little endian
        let prefix = &cmp.state.to_le_bytes()[0..2];
        if let Some(loc) = find_string_in_stmts(ptr1, prefix, stmts) {
            return Some((loc, ptr2));
        }
    }
    if cmp.operand2 > 0 && utils::is_in_shlib(ptr1) {
        crate::log_c!(
            trace,
            "cmp function ptr2: {:?} before stmt: {}, state: {:#04x} ",
            ptr2,
            stmt_index,
            { cmp.state }
        );
        let ret = find_location_at_ptr(stmts, ptr2, resource_states);
        if let Some(loc) = ret {
            return Some((loc, ptr1));
        }
        let prefix = &cmp.state.to_le_bytes()[2..4];
        if let Some(loc) = find_string_in_stmts(ptr2, prefix, stmts) {
            return Some((loc, ptr1));
        }
    }
    None
}

/// Search string in stmts
///
/// pointers may be released and overwrote after function called.
/// so we store its prefix or suffix as an slice for comparison.
pub fn find_string_in_stmts(
    _ptr: *mut u8,
    slice: &[u8],
    stmts: &[IndexedStmt],
) -> Option<Location> {
    if slice[0] == 0 {
        return None;
    }
    let mut slice = slice;
    if let Some(pos) = slice.iter().position(|c| *c == 0) {
        slice = &slice[..pos];
    }
    for indexed_stmt in stmts.iter().rev() {
        let index = &indexed_stmt.index;
        if let FuzzStmt::Load(load) = &indexed_stmt.stmt {
            if let Some(buf) = load.value.downcast_ref::<CanarySlice<u8>>() {
                let buf = buf.as_slice();
                crate::log_c!(trace, "search {slice:?} in {buf:?}");
                if let Some(i) = twoway::find_bytes(buf, slice) {
                    let fields = LocFields::new(vec![FieldKey::Index(i)]);
                    return Some(Location::new(index.use_index(), fields));
                }
            }
            if let Some(buf) = load.value.downcast_ref::<CanarySlice<i8>>() {
                crate::log_c!(trace, "search {slice:?} in {buf:?}");
                let buf = unsafe { std::slice::from_raw_parts(buf.ptr as *const u8, buf.len) };
                if let Some(i) = twoway::find_bytes(buf, slice) {
                    let fields = LocFields::new(vec![FieldKey::Index(i)]);
                    return Some(Location::new(index.use_index(), fields));
                }
            }
        }
    }
    None
}

pub fn dump_cmp_log() {
    use std::io::Write;
    CMP_STAT.with(|s| {
        let path = crate::config::output_file_path("misc/stat_cmp.csv");
        let mut f = std::fs::File::create(path).unwrap();
        writeln!(f, "id, cnt, diff").unwrap();
        let blk_path = crate::config::output_file_path("misc/stat_cmp.blacklist");
        let mut blk_f = std::fs::File::create(blk_path).unwrap();
        let s = s.borrow();
        for c in s.iter() {
            writeln!(f, "{}, {}, {}", c.0, c.1 .0, c.1 .1).unwrap();
            if c.1 .0 > 256 && !c.1 .1 {
                writeln!(blk_f, "{}", c.0).unwrap();
            }
        }
    });
}
