// FFI for E9/LLVM globls
#[cfg(any(feature = "e9_mode", feature = "llvm_mode"))]
extern "C" {
    fn __hopper_enable_cov();
    fn __hopper_disable_cov();
    fn __hopper_set_context(ctx: u32);
    fn __hopper_inc_stmt_index();
    fn __hopper_reset_stmt_index();
    fn __hopper_last_stmt_index();
    fn __hopper_get_stmt_index() -> u32;
}

#[inline]
pub fn disable_coverage_feedback() {
    #[cfg(any(feature = "e9_mode", feature = "llvm_mode"))]
    unsafe {
        __hopper_disable_cov();
    }
}

#[inline]
pub fn enable_coverage_feedback() {
    #[cfg(any(feature = "e9_mode", feature = "llvm_mode"))]
    unsafe {
        __hopper_enable_cov();
    }
}

#[inline]
pub fn set_coverage_context(_ctx: u32) {
    #[cfg(any(feature = "e9_mode", feature = "llvm_mode"))]
    unsafe {
        __hopper_set_context(_ctx);
    }
}

#[inline]
pub fn inc_rt_stmt_index() {
    #[cfg(any(feature = "e9_mode", feature = "llvm_mode"))]
    unsafe {
        __hopper_inc_stmt_index()
    }
}

#[inline]
pub fn reset_rt_stmt_index() {
    #[cfg(any(feature = "e9_mode", feature = "llvm_mode"))]
    unsafe {
        __hopper_reset_stmt_index()
    }
}

#[inline]
pub fn set_rt_last_stmt_index() {
    #[cfg(any(feature = "e9_mode", feature = "llvm_mode"))]
    unsafe {
        __hopper_last_stmt_index()
    }
}

// only for non e9 mode
#[inline]
pub fn current_stmt_index() -> u32 {
    #[cfg(not(feature = "llvm_mode"))]
    return 0_u32;
    #[cfg(feature = "llvm_mode")]
    unsafe { __hopper_get_stmt_index() }
}
