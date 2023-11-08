//! Wrapper for executing program
//! - wrap executing by fork, spwan ..
//! - handle errors
use std::{
    panic,
    sync::atomic::{compiler_fence, Ordering},
    time::Duration,
};

use super::StatusType;
use crate::{config, error::HopperError};

/// Executor for programs generaetd by Hopper
pub struct Executor {
    cnt: usize,
    timeout: Duration,
}

impl Default for Executor {
    fn default() -> Self {
        Self {
            cnt: 0,
            timeout: Duration::from_secs(1),
        }
    }
}

impl Executor {
    /// Set timeout
    pub fn set_timeout(&mut self, tmout: Duration) {
        self.timeout = tmout;
    }

    /// Return count
    pub fn count(&self) -> usize {
        self.cnt
    }

    /// Execute program and return status
    pub fn execute<T, F>(&mut self, fun: F) -> StatusType
    where
        F: FnOnce() -> eyre::Result<T>,
    {
        self.cnt += 1;
        // let _counter = self.usage.count();
        compiler_fence(Ordering::SeqCst);
        let res = self.fork_execute(fun);
        compiler_fence(Ordering::SeqCst);
        if let Err(err) = res {
            crate::log!(error, "{}-execute error: {:?}", self.cnt, err);
            match err {
                HopperError::ProcessCrash { pid: _, signal } => StatusType::Crash { signal },
                HopperError::ProcessTimeout { pid: _ } => StatusType::Timeout,
                _ => StatusType::Ignore,
            }
        } else {
            StatusType::default()
        }
    }

    /// Fork a new process and execute program
    ///
    /// the process can catch timeout and out of limited memory
    #[cfg(target_family = "unix")]
    fn fork_execute<T, F>(&self, fun: F) -> Result<(), HopperError>
    where
        F: FnOnce() -> eyre::Result<T>,
    {
        use nix::sys::{
            signal,
            wait::{waitpid, WaitStatus},
        };

        let start_at = std::time::Instant::now();
        match unsafe { nix::unistd::fork() } {
            Ok(nix::unistd::ForkResult::Parent { child, .. }) => {
                #[cfg(not(feature = "select_timeout"))]
                let res = {
                    let (sender, receiver) = std::sync::mpsc::channel();
                    let _ = std::thread::Builder::new().spawn(move || {
                        let res = waitpid(child, None).unwrap();
                        let _ = sender.send(res);
                    });
                    receiver.recv_timeout(self.timeout)
                };
                #[cfg(feature = "select_timeout")]
                let res = {
                    unsafe {
                        let _ = signal::signal(signal::SIGCHLD, signal::SigHandler::SigDfl);
                    }
                    let mut timeout_timeval = nix::sys::time::TimeVal::from(nix::libc::timeval {
                        tv_sec: self.timeout.as_secs() as i64,
                        tv_usec: 0,
                    });
                    let sres = nix::sys::select::select(0, None, None, None, &mut timeout_timeval);
                    match sres {
                        Ok(_) => Err(()),
                        Err(_) => Ok(waitpid(child, None).unwrap()),
                    }
                };
                match res {
                    Ok(status) => {
                        match status {
                            WaitStatus::Signaled(pid, signal, _) => {
                                Err(HopperError::ProcessCrash { pid, signal })
                            }
                            WaitStatus::Exited(pid, code) => {
                                // crate::log!(debug, "exited with code: {}", code);
                                // TODO: ASAN, MSAN
                                match code {
                                    config::ASSERT_ERROR_EXIT_CODE => {
                                        crate::log!(error, "assert error");
                                        Err(HopperError::ProcessCrash {
                                            pid,
                                            signal: signal::Signal::SIGABRT,
                                        })
                                    }
                                    config::DOUBLE_FREE_ERROR_EXIT_CODE => {
                                        crate::log!(error, "double free happened");
                                        Err(HopperError::ProcessCrash {
                                            pid,
                                            signal: signal::Signal::SIGABRT,
                                        })
                                    }
                                    config::EXEC_ERROR_EXIT_CODE => {
                                        crate::log!(error, "The program panic at rust side!");
                                        Err(HopperError::RuntimeError)
                                    }
                                    config::TIMEOUT_CODE => {
                                        Err(HopperError::ProcessTimeout { pid: child })
                                    }
                                    _ => Ok(()),
                                }
                            }
                            _ => Ok(()),
                        }
                    }
                    Err(_) => {
                        if signal::kill(child, signal::Signal::SIGKILL).is_err() {
                            crate::log!(error, "fail to kill child {}", child);
                        }
                        // if a wait is not performed, then the terminated child remains in a "zombie" state
                        // ATTN: the result can't be unwrap, if pid is nonexistent (it was finish),
                        // `waitpid` will return `Err(ECHILD)`
                        let _ = waitpid(child, None);
                        Err(HopperError::ProcessTimeout { pid: child })
                    }
                }
            }
            Ok(nix::unistd::ForkResult::Child) => {
                crate::log!(
                    trace,
                    "fork time: {} micro seconds",
                    start_at.elapsed().as_micros()
                );
                let ret = Self::execute_fn(fun);
                // return special signal if meet some error
                if let Err(e) = ret {
                    if let Some(he) = e.downcast_ref::<HopperError>() {
                        std::process::exit(error_to_exit_code(he));
                    }
                }
                std::process::exit(0);
            }
            Err(err) => Err(HopperError::ForkError(err.to_string())),
        }
    }

    #[cfg(target_os = "windows")]
    fn fork_execute<T, F>(&self, fun: F) -> Result<(), HopperError>
    where
        F: FnOnce() -> eyre::Result<T>,
    {
        let mut pi: crate::execute::ProcessInformation = crate::execute::ProcessInformation {
            hProcess: crate::execute::NULL,
            hThread: crate::execute::NULL,
            dwProcessId: 0,
            dwThreadId: 0,
        };
        match crate::execute::hopper_fork(&mut pi) {
            Ok(crate::execute::WinForkResult::Parent { child, .. }) => {
                crate::log!(
                    trace,
                    "fork child pid: {}, hProcess: {:?}, hThread: {:?}, dwProcessId: {}, dwThreadId: {}",
                    child,
                    pi.hProcess,
                    pi.hThread,
                    pi.dwProcessId,
                    pi.dwThreadId
                );
                match crate::execute::hopper_waitpid(&mut pi, config::WAIT_PID_TIMEOUT) {
                    Ok(status) => match status {
                        crate::execute::WinWaitStatus::Exited(code) => {
                            if code == config::EXEC_ERROR_EXIT_CODE as u32 {
                                crate::log!(error, "The program panic at rust side!");
                            }
                            crate::execute::close_child(pi);
                            Ok(())
                        }
                        crate::execute::WinWaitStatus::Crash(code) => {
                            crate::execute::close_child(pi);
                            Err(HopperError::ProcessCrash {
                                pid: child,
                                signal: code,
                            })
                        }
                        crate::execute::WinWaitStatus::Timeout(_code) => {
                            crate::execute::terminate_close_child(pi);
                            Err(HopperError::ProcessTimeout { pid: child })
                        }
                    },
                    Err(_) => {
                        crate::execute::terminate_close_child(pi);
                        Err(HopperError::ProcessTimeout { pid: child })
                    }
                }
            }
            Ok(crate::execute::WinForkResult::Child) => {
                crate::execute::register_execption_handler();
                crate::execute::register_signal_handler();
                let ret = Self::execute_fn(fun);
                // return special signal if meet some error
                if ret.is_err() {
                    if let Some(he) = ret.err().unwrap().downcast_ref::<HopperError>() {
                        std::process::exit(error_to_exit_code(he));
                    };
                } else {
                    std::process::exit(0);
                }
                Ok(())
            }
            Err(_) => Err(HopperError::ForkError(
                std::io::Error::last_os_error().to_string(),
            )),
        }
    }

    /// Spawn and execute program
    ///
    /// FIXME: It can't catch crash in FFI code
    #[cfg(feature = "spawn_execute")]
    fn spawn_execute<T, F>(&self, fun: F) -> eyre::Result<T>
    where
        F: FnOnce() -> crate::Result<T> + std::marker::Send,
        T: Send,
    {
        let res = crossbeam_utils::thread::scope(|s| {
            let (sender, receiver) = mpsc::channel();
            let handle = s.spawn(|_| {
                let res = Self::execute_fn(fun);
                let _ = sender.send(res);
                res
            });
            let res = receiver.recv_timeout(self.timeout).map_or(
                Err(HopperError::SpawnTimeout),
                |status| match status {
                    _ => Ok(()),
                },
            );
            // kill thread if timeout
            match handle.join() {
                Ok(_) => res,
                Err(err) => Err(HopperError::SpawnThreadPanic(err)),
            }
        });

        res.unwrap()
    }

    /// Execute programs generated by hopper directly
    ///
    /// It will ignore and print errors we defined in `eval`, and
    /// catch panics that is not caused by the foreighn functions in library.
    pub fn execute_fn<T, F>(fun: F) -> eyre::Result<T>
    where
        F: FnOnce() -> eyre::Result<T>,
    {
        match panic::catch_unwind(panic::AssertUnwindSafe(fun)) {
            Ok(ret) => ret,
            Err(err) => Err(eyre::eyre!(HopperError::UnwindPanic(err))),
        }
    }
}

fn error_to_exit_code(err: &HopperError) -> i32 {
    match err {
        HopperError::DoubleFree { .. } => config::DOUBLE_FREE_ERROR_EXIT_CODE,
        HopperError::AssertError { msg: _, silent } => {
            if *silent {
                config::ASSERT_SILENT_EXIT_CODE
            } else {
                config::ASSERT_ERROR_EXIT_CODE
            }
        }
        // ignore
        HopperError::UseAfterFree { .. } => config::UAF_ERROR_EXIT_CODE,
        _ => config::EXEC_ERROR_EXIT_CODE,
    }
}
