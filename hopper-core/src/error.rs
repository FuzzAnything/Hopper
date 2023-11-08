use std::any::Any;

use crate::execute::{Pid, Signal};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum HopperError {
    #[error("fail to fork, errno `{0}`")]
    ForkError(String),

    #[error("null function pointer")]
    NullFuncionPointer,

    #[error("OS Error: {errno}, caused by: {info}")]
    OSError { errno: std::io::Error, info: String },

    #[error("Catch unwind panic")]
    UnwindPanic(Box<dyn Any + Send + 'static>),

    #[error("Crash in child process, pid: `{pid}`, signal: `{signal}`")]
    ProcessCrash { pid: Pid, signal: Signal },

    #[error("Timeout in child process, pid: `{pid}`")]
    ProcessTimeout { pid: Pid },

    #[error("Panic at rust runtime")]
    RuntimeError,

    #[error("Assert error: `{msg}`")]
    AssertError{ msg: String, silent: bool },

    #[error("Use resource `{ptr:?}` after free")]
    UseAfterFree { ptr: *mut u8 },

    #[error("Free resource `{ptr:?}` more than once")]
    DoubleFree { ptr: *mut u8 },

    #[error("Test success")]
    TestSuccess,

    #[error("Fail to spawn thread")]
    SpawnThreadPanic(Box<dyn Any + Send + 'static>),

    #[error("Timeout in spawn thread")]
    SpawnTimeout,

    #[error("union field not found")]
    UnionErr,

    #[error("`{0}`")]
    FieldNotFound(String),

    #[error("Index does not exist in sequence")]
    IndexNotExist,

    #[error("Fail to read line: EOF")]
    ReadLineEOF,
}

unsafe impl Sync for HopperError {}
unsafe impl Send for HopperError {}

/// Get error number (errno) if return value less than zero, used for libc function calls.
pub fn check_os_error<T: Ord + Default>(num: T, msg: &str) -> Result<(), HopperError> {
    if num < T::default() {
        return Err(HopperError::OSError {
            errno: std::io::Error::last_os_error(),
            info: msg.to_string(),
        });
    }
    Ok(())
}
