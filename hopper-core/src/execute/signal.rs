//! Hook signal for handing
//!

use hopper_derive::Serde;

use crate::{CanaryInfo, FuzzProgram};

pub fn install_signal_handler() {
    // static mut PREV_HANDLER: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) = std::ptr::null_mut();
    if cfg!(test) || cfg!(not(any(feature = "e9_mode", feature = "llvm_mode"))) {
        return;
    }
    use nix::sys::signal;
    unsafe {
        // https://github.com/rust-lang/rust/issues/69533
        // https://github.com/rust-lang/rust/blob/master/library/std/src/sys/unix/stack_overflow.rs
        // the handler will overwrite rust's runtime to detect stack overflow.
        let sig_action = signal::SigAction::new(
            signal::SigHandler::SigAction(sigv_handler),
            signal::SaFlags::SA_SIGINFO
                | signal::SaFlags::SA_RESETHAND
                | signal::SaFlags::SA_ONSTACK,
            signal::SigSet::empty(),
        );
        for signal in [signal::SIGSEGV, signal::SIGBUS] {
            let ret = signal::sigaction(signal, &sig_action);
            if let Err(err) = ret {
                crate::log!(error, "fail to install signal hook: {:?}", err);
            }
        }
    }
    crate::log!(trace, "install signal handler!");
}

extern "C" fn sigv_handler(
    _sig: libc::c_int,
    si: *mut libc::siginfo_t,
    _unused: *mut libc::c_void,
) {
    println!("signal ! {_sig}");
    unsafe {
        if let Some(si) = si.as_ref() {
            // println!("Got SIGSEGV at address: {:?}\n", si.si_addr());
            let addr = si.si_addr() as u64;
            let instrs = crate::feedback::get_instr_list_mut();
            instrs.segv_addr = addr;
        }
        #[cfg(target_os = "linux")]
        if let Some(context) = (_unused as *mut libc::ucontext_t).as_ref() {
            let rip = context.uc_mcontext.gregs[libc::REG_RIP as usize];
            let instrs = crate::feedback::get_instr_list_mut();
            instrs.rip_addr = rip as u64;
        }
    }
}

#[cfg(target_family = "unix")]
impl crate::Serialize for super::Signal {
    fn serialize(&self) -> eyre::Result<String> {
        Ok(self.to_string() + "$")
    }
}

#[cfg(target_family = "unix")]
impl crate::Deserialize for super::Signal {
    fn deserialize(de: &mut crate::Deserializer) -> eyre::Result<Self> {
        let signal: super::Signal = de.parse_next_until("$")?;
        Ok(signal)
    }
}

#[derive(Debug, Serde, Clone)]
pub struct CrashSig {
    // segv address
    pub addr: u64,
    // crash RIP
    pub rip: u64,
    // crash path's hash
    pub hash: u64,
    // overflow canary
    canary: Option<CanaryInfo>,
}

pub fn get_crash_sig(program: Option<&FuzzProgram>) -> Option<CrashSig> {
    let addr = get_segv_addr();
    if addr != crate::config::DEFAULT_SEGV_ADDR {
        let rip = get_rip_addr();
        let mut oa = CrashSig {
            addr,
            rip,
            hash: 0,
            canary: None,
        };
        if let Some(p) = program {
            if let Some(info) = crate::canary::find_ptr_in_canary(p, addr as *mut u8) {
                oa.canary = Some(info);
            }
        }
        return Some(oa);
    }
    None
}

#[inline]
pub fn is_overflow_canary() -> bool {
    let addr = get_segv_addr() as *mut u8;
    crate::canary::is_in_canary(addr)
}

pub fn is_access_null() -> bool {
    let addr = get_segv_addr();
    addr < 0x2000
}

pub fn is_overflow_canary_at_rip(_rip: u64) -> bool {
    #[cfg(target_os = "linux")]
    if get_rip_addr() != _rip {
        return false;
    }
    let addr = get_segv_addr() as *mut u8;
    crate::canary::is_in_canary(addr)
}

#[inline]
pub fn get_segv_addr() -> u64 {
    let instr = crate::get_instr_list();
    instr.segv_addr
}

#[inline]
pub fn get_rip_addr() -> u64 {
    let instr = crate::get_instr_list();
    instr.rip_addr
}

impl CrashSig {
    /// access null pointer
    /// 0x100 may be offset
    pub fn is_null_access(&self) -> bool {
        self.addr < 0x2000
    }

    /// overflow in canary
    pub fn is_overflow_canary(&self) -> bool {
        crate::canary::is_in_canary(self.addr as *mut u8)
    }

    /// is stack overflow
    pub fn is_stack_overflow(&self) -> bool {
        self.addr > 0x7ff000000000
    }

    pub fn get_addr(&self) -> *const u8 {
        self.addr as *const u8
    }

    pub fn get_rip(&self) -> *const u8 {
        self.rip as *const u8
    }

    pub fn get_canary_info(&self) -> Option<&CanaryInfo> {
        self.canary.as_ref()
    }

    pub fn is_null_function_pointer(&self) -> bool {
        self.is_null_access() && self.rip == 0
    }

    pub fn is_overflow_at_same_rip(&self) -> bool {
        is_overflow_canary_at_rip(self.rip)
    }

    pub fn is_overflow_at_same_canary(&self) -> bool {
        let segv_addr = get_segv_addr();
        if segv_addr > 0 {
            let page_size = region::page::size() as u64;
            if segv_addr > self.addr {
                return segv_addr - self.addr < page_size;
            } else {
                return self.addr - segv_addr < page_size;
            }
        }
        false
    }

    pub fn is_overflow_at_same_rip_or_canary(&self) -> bool {
        crate::log!(trace, "rpi: {}, segv: {}", get_rip_addr(), get_segv_addr());
        self.is_overflow_at_same_rip() || self.is_overflow_at_same_canary()
    }

    pub fn reason(&self) -> String {
        if self.is_null_function_pointer() {
            return "access null function pointer".to_string();
        }
        if self.is_null_access() {
            return "access null pointer".to_string();
        }
        if let Some(canary) = self.get_canary_info() {
            return format!(
                "overflow in hopper canary, stmt index: {}, len: {}",
                canary.stmt_index, canary.len
            );
        }
        if self.is_stack_overflow() {
            return "overflow in stack".to_string();
        }
        "unoknow".to_string()
    }
}
