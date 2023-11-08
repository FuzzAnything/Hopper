mod executor;
mod forkcli;
mod forksrv;
pub mod io_utils;
mod limit;
mod signal;

pub use executor::*;
pub use forkcli::*;
pub use forksrv::*;
pub use signal::*;

use hopper_derive::Serde;

#[cfg(target_family = "unix")]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(target_os = "windows")]
use uds_windows::{UnixListener, UnixStream};

#[cfg(target_family = "unix")]
pub use nix::sys::signal::Signal;
#[cfg(target_os = "windows")]
pub type Signal = u32;

#[cfg(target_family = "unix")]
pub use nix::unistd::Pid;
#[cfg(target_os = "windows")]
pub type Pid = u32;

#[cfg(target_os = "windows")]
pub mod forklib_win;
#[cfg(target_os = "windows")]
pub use forklib_win::*;

/// Status type of program's executing result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serde)]
pub enum StatusType {
    /// program runs OK
    Normal,
    /// program runs timeout
    Timeout,
    /// program crash
    Crash { signal: Signal },
    /// Ignored cases (error) during executing
    Ignore,
    /// Loop is endding
    LoopEnd
}

impl Default for StatusType {
    fn default() -> Self {
        Self::Normal
    }
}

impl StatusType {
    pub fn is_normal(&self) -> bool {
        matches!(self, Self::Normal)
    }
    pub fn is_ignore(&self) -> bool {
        matches!(self, Self::Ignore)
    }
    pub fn is_crash(&self) -> bool {
        matches!(self, Self::Crash { signal: _ })
    }
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout)
    }
    pub fn is_loop_end(&self) -> bool {
        matches!(self, Self::LoopEnd)
    }
    pub fn is_abort(&self) -> bool {
        matches!(
            self,
            StatusType::Crash {
                signal: Signal::SIGABRT
            }
        )
    }
    pub fn is_sigfpe(&self) -> bool {
        matches!(
            self,
            StatusType::Crash {
                signal: Signal::SIGFPE
            }
        )
    }
    pub fn is_overflow(&self) -> bool {
        matches!(
            self,
            StatusType::Crash {
                signal: Signal::SIGSEGV
            } | StatusType::Crash {
                signal: Signal::SIGBUS
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serde)]
pub enum ForkCmd {
    Execute,
    Loop,
    Review,
    Sanitize,
    Config(String),
    Finish,
}

pub static OPAQUE_CONFIG_KEY: &str = "opaque";
