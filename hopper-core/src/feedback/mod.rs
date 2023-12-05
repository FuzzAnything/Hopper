mod branches;
mod cmp;
pub mod globl;
mod instr;
mod mem;
mod observer;
mod ops;
mod path;
mod res;
mod review;
mod sanitize;
mod hook;

pub use branches::*;
pub use cmp::*;
pub use instr::*;
pub use mem::*;
pub use observer::*;
pub use ops::*;
pub use path::*;
pub use res::*;
pub use review::*;
pub use sanitize::*;
pub use hook::add_hooks;

#[cfg(target_family = "unix")]
mod shm;
#[cfg(target_os = "windows")]
mod shm_win;
#[cfg(target_family = "unix")]
pub use shm::*;
#[cfg(target_os = "windows")]
pub use shm_win::*;

/// Feedback of program execution, including branch/coverage feedback
pub struct Feedback {
    // executed edges
    pub path: SharedMemory<Path>,
    // executed instructions, e.g. cmp, malloc..
    pub instrs: SharedMemory<InstrList>,
}

#[derive(Default, Debug)]
pub struct FeedbackSummary {
    // micro secs
    pub time_used: u128,
    // path's length
    pub path_len: usize,
    // is it reach uniq new path
    pub has_new_uniq_path: bool,
}

pub static mut INSTR_LIST: *mut InstrList = std::ptr::null_mut();

pub fn get_instr_list<'a>() -> &'a InstrList {
    unsafe { &*INSTR_LIST }
}

pub fn get_instr_list_mut<'a>() -> &'a mut InstrList {
    unsafe { &mut *INSTR_LIST }
}

impl Feedback {
    pub fn new() -> eyre::Result<Self> {
        let feedback = Self {
            path: setup_shm()?,
            instrs: setup_shm()?,
        };
        unsafe {
            INSTR_LIST = feedback.instrs.ptr;
        }
        Ok(feedback)
    }

    pub fn clear(&mut self) {
        self.path.clear();
        self.instrs.inner_clear();
        // mark share memory works!
        self.path.buf[0] = 1;
        // set func addr
        self.instrs.set_mem_fn();
    }

    /// Get last stmt index
    pub fn last_stmt_index(&self) -> usize {
        self.instrs.last_stmt_index()
    }

    // Our path tracking find nothing (none edge)
    // the program exit before invoking the target function that we want to track
    pub fn track_nothing(&self) -> bool {
        self.path.get_list().len() <= 1
    }
}

pub trait SHMable {
    fn name() -> &'static str;
    fn shmid_env_var() -> &'static str;
    fn ptr_base() -> *const libc::c_void;
    fn buf_size() -> usize;
    fn post_hander(_ptr: *const u8) {}
}
