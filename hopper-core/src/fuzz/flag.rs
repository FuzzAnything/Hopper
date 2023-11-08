use super::rng::*;
use std::cell::Cell;

thread_local! {
    // Deterministic generation in pilot phase
    pub static PILOT_DET: Cell<bool> = Cell::new(false);
    // Generate only single call
    pub static SINGLE_CALL: Cell<bool> = Cell::new(true);
    // Reuse statement in generation
    pub static REUSE_STMT: Cell<bool> = Cell::new(false);
    // Only mutate argument inputs.
    pub static INPUT_ONLY: Cell<bool> = Cell::new(false);
    // Refine successful or not
    pub static REFINE_SUC: Cell<bool> = Cell::new(false);
    // Mutate pointer or not
    pub static MUTATE_PTR: Cell<bool> = Cell::new(false);
    // deterministic mutation for call
    pub static CALL_DET: Cell<bool> = Cell::new(false);
    // Generate an incomplete program
    pub static INCOMPLETE_GEN: Cell<bool> = Cell::new(false);
    // Running in pilot infer phase
    pub static PILOT_INFER: Cell<bool> = Cell::new(false);
    // u64 temp value
    pub static TMP_U64: Cell<u64> = Cell::new(0);
}

pub fn is_pilot_det() -> bool {
    PILOT_DET.with(|c| c.get())
}

pub fn set_pilot_det(flag: bool) -> bool {
    PILOT_DET.with(|c| c.replace(flag))
}

pub fn is_single_call() -> bool {
    SINGLE_CALL.with(|c| c.get())
}

pub fn set_single_call(flag: bool) -> bool {
    SINGLE_CALL.with(|c| c.replace(flag))
}

pub fn is_reuse_stmt() -> bool {
    REUSE_STMT.with(|c| c.get())
}

pub fn set_reuse_stmt(flag: bool) -> bool {
    REUSE_STMT.with(|c| c.replace(flag))
}

pub fn is_input_only() -> bool {
    INPUT_ONLY.with(|c| c.get())
}

pub fn set_input_only(flag: bool) -> bool {
    INPUT_ONLY.with(|c| c.replace(flag))
}

pub fn is_refine_suc() -> bool {
    REFINE_SUC.with(|c| c.get())
}

pub fn set_refine_suc(flag: bool) -> bool {
    REFINE_SUC.with(|c| c.replace(flag))
}

pub fn is_mutate_ptr() -> bool {
    MUTATE_PTR.with(|c| c.get())
}

pub fn set_mutate_ptr(flag: bool) -> bool {
    MUTATE_PTR.with(|c| c.replace(flag))
}

pub fn is_incomplete_gen() -> bool {
    INCOMPLETE_GEN.with(|c| c.get())
}

pub fn set_incomplete_gen(flag: bool) -> bool {
    INCOMPLETE_GEN.with(|c| c.replace(flag))
}

pub fn is_pilot_infer() -> bool {
    PILOT_INFER.with(|c| c.get())
}

pub fn set_pilot_infer(flag: bool) -> bool {
    PILOT_INFER.with(|c| c.replace(flag))
}

pub fn set_tmp_u64(val: u64) {
    TMP_U64.with(|c| c.replace(val));
}

pub fn get_tmp_u64() -> u64 {
    TMP_U64.with(|c| c.get())
}

/// Enable call's deterministic mutation
pub fn enable_call_det() {
    CALL_DET.with(|c| {
        if c.get() && std::env::var("DISABLE_CALL_DET").is_err() {
            crate::log!(info, "start enable call det!");
            c.replace(true);
        }
    });
}

pub fn disable_call_det() {
    CALL_DET.with(|c| c.replace(false));
}

pub fn is_call_det() -> bool {
    CALL_DET.with(|c| c.get())
}

/// decide whether to use call or not
/// type_name is inner type of pointer
pub fn use_call(inner_type: &str, is_opaque: bool, depth: usize) -> bool {
    if depth >= crate::config::MAX_DEPTH {
        return false;
    }
    if is_opaque {
        return is_pilot_det() || mostly();
    }
    if is_single_call() {
        return false;
    }
    // de-prioritize primitive pointer
    if crate::utils::is_primitive_type(inner_type) {
        return rarely();
    }
    unlikely()
}

pub fn get_mutate_flag() -> u8 {
    let mut flag: u8 = 0;
    if is_pilot_det() {
        flag |= 1;
    }
    if is_single_call() {
        flag |= 2;
    }
    if is_reuse_stmt() {
        flag |= 4;
    }
    flag
}

pub fn set_mutate_flag(flag: u8) {
    set_pilot_det(flag & 1 > 0);
    set_single_call(flag & 2 > 0);
    set_reuse_stmt(flag & 4 > 0);
}

pub struct ReuseStmtGuard {
    cur: bool,
}

impl ReuseStmtGuard {
    // disable reuse stmt in the scope
    pub fn temp_disable() -> Self {
        REUSE_STMT.with(|cell| {
            Self { cur: cell.replace(false) }
        })
    }
}

impl Drop for ReuseStmtGuard {
    fn drop(&mut self) {
        set_reuse_stmt(self.cur);
    }
}
