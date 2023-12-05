//! Program for fuzzing

use std::fmt::Write as _;
use std::{
    cell::RefCell,
    fmt,
    hash::{Hash, Hasher},
    rc::Rc,
};

use super::*;
use crate::{
    feedback::{CmpOperation, ResourceStates, ReviewCollector, SanitizeChecker, globl},
    log, MutateOperator, RngState,
};

/// Program for fuzzing
#[derive(Debug, Default)]
pub struct FuzzProgram {
    // Id of ther current program,
    pub id: usize,
    // This program's parent
    pub parent: Option<usize>,
    /// Statements
    pub stmts: Vec<IndexedStmt>,
    /// Compare operations, we can mutate them after clone
    pub cmps: Rc<Vec<Rc<RefCell<CmpOperation>>>>,
    /// Operators
    pub ops: Vec<MutateOperator>,
    /// Temperal indices
    pub tmp_indices: Vec<StmtIndex>,
    /// rng
    pub rng: Option<RngState>,
    /// mutate flag
    pub mutate_flag: u8,
}

impl FuzzProgram {
    /// Eval this program
    pub fn eval(&mut self) -> eyre::Result<()> {
        globl::reset_rt_stmt_index();
        let mut resource_states = ResourceStates::default();
        for i in 0..self.stmts.len() {
            let (used_stmts, unused) = self.stmts.split_at_mut(i);
            log!(trace, "{}", unused[0].serialize()?.trim_end());
            unused[0].stmt.eval(used_stmts, &mut resource_states)?;
            globl::inc_rt_stmt_index();
        }
        globl::set_rt_last_stmt_index();
        Ok(())
    }

    /// Review the program
    pub fn review(&mut self) -> eyre::Result<()> {
        static mut REVIEWING: bool = false;
        static mut STMTS: *const IndexedStmt = std::ptr::null();
        static mut COLLECTOR: *mut ReviewCollector = std::ptr::null_mut();
        static mut STATE: *const ResourceStates = std::ptr::null();
        extern "C" fn on_exit() {
            // it can't hook SIGKILL
            if unsafe { !REVIEWING } {
                return;
            }
            #[cfg(not(test))]
            unsafe {
                crate::utils::LOG_COND = false
            };
            let instrs = crate::feedback::get_instr_list();
            let index = instrs.last_stmt_index() as usize;
            println!("exit at {index}..");
            let used_stmts = unsafe { std::slice::from_raw_parts(STMTS, index) };
            let cur = unsafe { &*STMTS.add(index) };
            if let FuzzStmt::Call(call) = &cur.stmt {
                let rc: &mut ReviewCollector = unsafe { &mut *COLLECTOR };
                let state: &ResourceStates = unsafe { &*STATE };
                println!("call {}..", call.name);
                // logger is thead local and can not call at exit,
                // so we should sure this function won't log sth by RUST_LOG=info
                let ret = rc.collect_call_review(call, index, used_stmts, state);
                if let Err(err) = ret {
                    println!("err: {err:?}");
                }
            }
            unsafe {
                REVIEWING = false;
            }
        }
        let mut review_collector = Box::new(ReviewCollector::new(self.id)?);
        let mut resource_states = Box::<ResourceStates>::default();
        unsafe {
            libc::atexit(on_exit);
            REVIEWING = true;
            STMTS = self.stmts.as_ptr();
            COLLECTOR = review_collector.as_mut() as *mut ReviewCollector;
            STATE = resource_states.as_ref() as *const ResourceStates;
        }
        globl::reset_rt_stmt_index();
        resource_states.set_review();
        for i in 0..self.stmts.len() {
            let (used_stmts, unused) = self.stmts.split_at_mut(i);
            log!(trace, "{}", unused[0].serialize()?.trim_end());
            unused[0].stmt.eval(used_stmts, &mut resource_states)?;
            if let FuzzStmt::Call(call) = &unused[0].stmt {
                review_collector.collect_call_review(call, i, used_stmts, &resource_states)?;
            }
            globl::inc_rt_stmt_index();
        }
        globl::set_rt_last_stmt_index();
        unsafe {
            REVIEWING = false;
        }
        Ok(())
    }

    /// Sanitize the program, try to find false positive in crashes
    pub fn sanitize(&mut self) -> eyre::Result<()> {
        let mut checker = SanitizeChecker::new()?;
        globl::reset_rt_stmt_index();
        let mut resource_states = ResourceStates::default();
        resource_states.set_review();
        for i in 0..self.stmts.len() {
            let (used_stmts, unused) = self.stmts.split_at_mut(i);
            log!(trace, "{}", unused[0].serialize()?.trim_end());
            checker.check_before_eval_stmt(&unused[0], used_stmts, &resource_states)?;
            unused[0].stmt.eval(used_stmts, &mut resource_states)?;
            globl::inc_rt_stmt_index();
        }
        globl::set_rt_last_stmt_index();
        Ok(())
    }

    /// Append new statement
    pub fn append_stmt<T: Into<FuzzStmt>>(&mut self, stmt: T) -> StmtIndex {
        let indexed_stmt = IndexedStmt::new(stmt.into(), self.stmts.len());
        let use_index = indexed_stmt.index.use_index();
        self.stmts.push(indexed_stmt);
        use_index
    }

    /// Insert new statement
    pub fn insert_stmt<T: Into<FuzzStmt>>(&mut self, index: usize, stmt: T) -> StmtIndex {
        let indexed_stmt = IndexedStmt::new(stmt.into(), index);
        let use_index = indexed_stmt.index.use_index();
        self.stmts.insert(index, indexed_stmt);
        self.resort_indices();
        use_index
    }

    /// Insert or append new statement
    pub fn insert_or_append_stmt<T: Into<FuzzStmt>>(&mut self, stmt: T) -> eyre::Result<StmtIndex> {
        let stmt = if let Some(stub_index) = self.get_stub_stmt_index() {
            // mutate mode
            self.insert_stmt(stub_index.get(), stmt)
        } else {
            self.append_stmt(stmt)
        };
        Ok(stmt)
    }

    /// Delete statment at `index`
    pub fn delete_stmt(&mut self, index: usize) {
        // log!(trace, "delete stmt index: {:?}", index);
        let _is = self.stmts.remove(index);
        // self.tmp_indices.push(stmt.index);
        self.resort_indices();
    }

    /// Resort indices of statement,
    /// it was called after insert or delete statements
    pub fn resort_indices(&mut self) {
        for (i, indexed_stmt) in self.stmts.iter_mut().enumerate() {
            indexed_stmt.index.set(i);
        }
    }

    /// Withdraw the statement we have lent
    pub fn withdraw_stmt(&mut self, stmt: FuzzStmt) -> eyre::Result<StmtIndex> {
        let is = self
            .stmts
            .iter_mut()
            .find(|is| is.stmt.is_stub())
            .ok_or_else(|| eyre::eyre!("can't find any stub stmt"))?;
        let index = is.index.use_index();
        let _ = std::mem::replace(&mut is.stmt, stmt);
        Ok(index)
    }

    /// Save mutate state for replay
    pub fn save_mutate_state(&mut self) {
        let rng_cur = crate::save_rng_state();
        self.rng = Some(rng_cur);
        self.mutate_flag = crate::get_mutate_flag();
        self.ops = vec![];
    }

    /// Get index that is stub type
    pub fn get_stub_stmt_index(&self) -> Option<StmtIndex> {
        self.stmts
            .iter()
            .find(|is| is.stmt.is_stub())
            .map(|is| is.index.use_index())
    }

    /// Get failure stmt
    pub fn get_fail_stmt_index(&self) -> Option<StmtIndex> {
        self.stmts
            .iter()
            .find(|is| {
                if let FuzzStmt::Call(call) = &is.stmt {
                    if call.failure {
                        return true;
                    }
                }
                false
            })
            .map(|is| is.index.use_index())
    }

    /// Get statement by loc's index
    pub fn get_stmt_by_loc(&self, loc: &impl RcLocation) -> eyre::Result<&IndexedStmt> {
        self.stmts
            .get(loc.get_index()?.get())
            .ok_or_else(|| eyre::eyre!("index in loc out of bound stmt"))
    }

    /// Get i-th stmt
    pub fn get_stmt(&self, index: usize) -> eyre::Result<&IndexedStmt> {
        if let Some(is) = self.stmts.get(index) {
            return Ok(is);
        }
        eyre::bail!(format!(
            "fail to get {index} in program, length: {}",
            self.stmts.len()
        ))
    }

    /// Get target stmt
    pub fn get_target_stmt(&self) -> Option<&CallStmt> {
        if let Some(is) = self.stmts.last() {
            match &is.stmt {
                FuzzStmt::Call(call) => return Some(call),
                FuzzStmt::Assert(assert) => {
                    if let Some(stmt) = assert.get_stmt() {
                        if let FuzzStmt::Call(call) = &self.stmts[stmt.get()].stmt {
                            return Some(call);
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Get index of target stmt
    pub fn get_target_index(&self) -> Option<usize> {
        if let Some(is) = self.stmts.last() {
            match &is.stmt {
                FuzzStmt::Call(_) => return Some(is.index.get()),
                FuzzStmt::Assert(assert) => {
                    if let Some(stmt) = assert.get_stmt() {
                        if let FuzzStmt::Call(_) = &self.stmts[stmt.get()].stmt {
                            return Some(stmt.get());
                        }
                    }
                }
                _ => {
                    crate::log!(error, "last stmt is: {:?}", is.serialize().unwrap());
                }
            }
        } 
        None
    }

    /// Get i-th call stmt
    pub fn get_call_stmt(&self, index: usize) -> Option<&CallStmt> {
        if let Some(is) = self.stmts.get(index) {
            if let FuzzStmt::Call(call) = &is.stmt {
                return Some(call);
            }
        }
        None
    }

    /// Get i-th call stmt
    pub fn get_call_stmt_mut(&mut self, index: usize) -> Option<&mut CallStmt> {
        if let Some(is) = self.stmts.get_mut(index) {
            if let FuzzStmt::Call(call) = &mut is.stmt {
                return Some(call);
            }
        }
        None
    }

    /// Get the failed call stmt
    pub fn get_fail_call_stmt(&self) -> Option<&CallStmt> {
        if let Some(fail_at) = self.get_fail_stmt_index() {
            if let Some(call) = self.get_call_stmt(fail_at.get()) {
                return Some(call);
            }
        }
        None
    }

    /// Get stmt by index uniq
    pub fn get_stmt_by_index_uniq<T: RcIndex + ?Sized>(&self, index: &T) -> Option<&IndexedStmt> {
        let index_uniq = index.get_uniq();
        let index_val = index.get();
        // return quickly if they are matched
        if index_val < self.stmts.len() {
            let is = &self.stmts[index.get()];
            if is.index.get_uniq() == index_uniq {
                return Some(is);
            }
        }
        self.stmts
            .iter()
            .find(|is| is.index.get_uniq() == index_uniq)
    }

    /// Get mut stmt by index uniq
    pub fn get_mut_stmt_by_index_uniq<T: RcIndex + ?Sized>(
        &mut self,
        index: &T,
    ) -> Option<&mut IndexedStmt> {
        let index_uniq = index.get_uniq();
        self.stmts
            .iter_mut()
            .find(|is| is.index.get_uniq() == index_uniq)
    }

    ///  Get position of stmt by uniq
    pub fn position_stmt_by_index_uniq<T: RcIndex + ?Sized>(&mut self, index: &T) -> Option<usize> {
        let index_uniq = index.get_uniq();
        self.stmts
            .iter()
            .position(|is| is.index.get_uniq() == index_uniq)
    }

    /// Clone without state information
    pub fn clone_without_state(&self) -> eyre::Result<Self> {
        let output = self.serialize()?;
        let mut p = read_program(&output, false)?;
        // clone ops
        let op_output = self.ops.serialize()?;
        let mut de = Deserializer::new(&op_output, Some(&mut p));
        let ops = Vec::<MutateOperator>::deserialize(&mut de)?;
        p.ops = ops;
        p.rng = self.rng.clone();
        p.mutate_flag = self.mutate_flag;
        Ok(p)
    }

    /// Set all calls's track_cov
    pub fn set_calls_track_cov(&mut self, track_cov: bool) -> bool {
        let mut changed = false;
        for is in self.stmts.iter_mut() {
            if let FuzzStmt::Call(call) = &mut is.stmt {
                if call.track_cov != track_cov {
                    call.track_cov = track_cov;
                    changed = true;
                }
            }
        }
        changed
    }

    /// find all track calls
    pub fn get_track_calls(&self) -> Vec<u64> {
        let mut track_calls = vec![];
        for is in &self.stmts {
            if let FuzzStmt::Call(call) = &is.stmt {
                if call.track_cov {
                    track_calls.push(is.index.get_uniq());
                }
            }
        }
        track_calls
    }

    /// Check if any tmp index is unused, and then clear all of them
    pub fn clear_tmp_indices(&mut self) -> eyre::Result<()> {
        for i in &self.tmp_indices {
            if i.get_ref_used() == 1 {
                log!(warn, "program: {}", self.serialize()?);
                eyre::bail!("index {:?} is unused", i);
            }
        }
        self.tmp_indices.clear();
        Ok(())
    }

    /// serialize all with rng, ops ...
    pub fn serialize_all(&self) -> eyre::Result<String> {
        let mut buf = self.serialize()?;
        if let Some(rng) = &self.rng {
            let _ = writeln!(buf, "<RNG> {}", rng.serialize()?);
        }
        let _ = writeln!(buf, "<FLAG> {}", self.mutate_flag);
        if !self.ops.is_empty() {
            let _ = writeln!(buf, "<OP> {}", self.ops.serialize()?);
        }
        Ok(buf)
    }
}

pub trait CloneProgram {
    /// Clone with program
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self;
}

impl Clone for FuzzProgram {
    fn clone(&self) -> Self {
        let mut p = Self {
            id: self.id,
            parent: self.parent,
            stmts: vec![],
            cmps: self.cmps.clone(),
            ops: vec![],
            tmp_indices: vec![],
            rng: self.rng.clone(),
            mutate_flag: self.mutate_flag,
        };
        for stmt in self.stmts.iter() {
            let stmt = stmt.clone_with_program(&mut p);
            p.stmts.push(stmt);
        }
        p.clear_tmp_indices().unwrap();
        p
    }
}

impl PartialEq for FuzzProgram {
    fn eq(&self, other: &FuzzProgram) -> bool {
        self.id == other.id
    }
}

impl Eq for FuzzProgram {}

impl Hash for FuzzProgram {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// Just disply sth
impl fmt::Display for FuzzProgram {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.serialize_all().unwrap())
    }
}

#[test]
fn test_stmt_insert() {
    let mut program = FuzzProgram::default();
    let load = LoadStmt::generate_new(&mut program, "u64", "test", 0).unwrap();
    let _index = program.append_stmt(load);
    let load2 = LoadStmt::generate_new(&mut program, "i32", "test", 0).unwrap();
    let _index2 = program.insert_stmt(0, load2);
    let load3 = LoadStmt::generate_new(&mut program, "char", "test", 0).unwrap();
    let _index3 = program.insert_stmt(0, load3);
    for (i, stmt) in program.stmts.iter().enumerate() {
        assert!(stmt.index.get() == i)
    }
}
