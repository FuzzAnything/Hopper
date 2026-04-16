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

#[cfg(feature = "cov_mode")]
pub mod cov_impl {
    pub fn enable_cov() {}
    pub fn disable_cov() {}
    pub fn set_context(_ctx: u32) {}

    pub fn inc_stmt_index() {
        use crate::feedback::instr::__hopper_stmt_index_ptr;
        unsafe {
            if !__hopper_stmt_index_ptr.is_null() {
                let index = *__hopper_stmt_index_ptr;
                *(__hopper_stmt_index_ptr as *mut u32) = index + 1;
            }
        }
    }

    pub fn reset_stmt_index() {
        use crate::feedback::instr::__hopper_stmt_index_ptr;
        unsafe {
            if !__hopper_stmt_index_ptr.is_null() {
                *(__hopper_stmt_index_ptr as *mut u32) = 0;
            }
        }
    }

    pub fn last_stmt_index() {
        use crate::feedback::instr::__hopper_stmt_index_ptr;
        unsafe {
            if !__hopper_stmt_index_ptr.is_null() {
                *(__hopper_stmt_index_ptr as *mut u32) = 0xFFFF;
            }
        }
    }

    pub fn get_stmt_index() -> u32 {
        use crate::feedback::instr::__hopper_stmt_index_ptr;
        unsafe {
            if !__hopper_stmt_index_ptr.is_null() {
                *__hopper_stmt_index_ptr
            } else {
                0
            }
        }
    }
}

#[inline]
pub fn disable_coverage_feedback() {
    #[cfg(any(feature = "e9_mode", feature = "llvm_mode"))]
    unsafe {
        __hopper_disable_cov();
    }
    #[cfg(feature = "cov_mode")]
    cov_impl::disable_cov();
}

#[inline]
pub fn enable_coverage_feedback() {
    #[cfg(any(feature = "e9_mode", feature = "llvm_mode"))]
    unsafe {
        __hopper_enable_cov();
    }
    #[cfg(feature = "cov_mode")]
    cov_impl::enable_cov();
}

#[inline]
pub fn set_coverage_context(_ctx: u32) {
    #[cfg(any(feature = "e9_mode", feature = "llvm_mode"))]
    unsafe {
        __hopper_set_context(_ctx);
    }
    #[cfg(feature = "cov_mode")]
    cov_impl::set_context(_ctx);
}

#[inline]
pub fn inc_rt_stmt_index() {
    #[cfg(any(feature = "e9_mode", feature = "llvm_mode"))]
    unsafe {
        __hopper_inc_stmt_index()
    }
    #[cfg(feature = "cov_mode")]
    cov_impl::inc_stmt_index();
}

#[inline]
pub fn reset_rt_stmt_index() {
    #[cfg(any(feature = "e9_mode", feature = "llvm_mode"))]
    unsafe {
        __hopper_reset_stmt_index()
    }
    #[cfg(feature = "cov_mode")]
    cov_impl::reset_stmt_index();
}

#[inline]
pub fn set_rt_last_stmt_index() {
    #[cfg(any(feature = "e9_mode", feature = "llvm_mode"))]
    unsafe {
        __hopper_last_stmt_index()
    }
    #[cfg(feature = "cov_mode")]
    cov_impl::last_stmt_index();
}

// only for non e9 mode
#[inline]
pub fn current_stmt_index() -> u32 {
    #[cfg(not(any(feature = "llvm_mode", feature = "cov_mode")))]
    return 0_u32;
    #[cfg(feature = "llvm_mode")]
    unsafe { __hopper_get_stmt_index() }
    #[cfg(feature = "cov_mode")]
    return cov_impl::get_stmt_index();
}
