//! Limitation of memory and time

pub trait SetLimit {
    /// Limit memory
    fn mem_limit(&mut self, size: Option<u64>) -> &mut Self;
    /// Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
    /// before the dump is complete
    fn core_limit(&mut self) -> &mut Self;
    /// Isolate the process and configure standard descriptors.
    fn setsid(&mut self) -> &mut Self;
    /// Isolate the process into a new network namespace (Linux only).
    /// Blocks all network access except AF_UNIX sockets used by IPC.
    fn net_isolate(&mut self) -> &mut Self;
}

#[cfg(target_family = "unix")]
use std::{os::unix::process::CommandExt, process::Command};
#[cfg(target_family = "unix")]
impl SetLimit for Command {
    fn mem_limit(&mut self, size: Option<u64>) -> &mut Self {
        if let Some(size) = size {
            let func = move || {
                if size > 0 {
                    let size = size << 20;
                    let mem_limit: libc::rlim_t = size;
                    let r = libc::rlimit {
                        rlim_cur: mem_limit,
                        rlim_max: mem_limit,
                    };
                    unsafe {
                        #[cfg(any(target_os = "linux", target_os = "macos"))]
                        libc::setrlimit(libc::RLIMIT_AS, &r);
                        // This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
                        // according to reliable sources, RLIMIT_DATA covers anonymous
                        // maps - so we should be getting good protection against OOM bugs
                        #[cfg(target_os = "freebsd")]
                        libc::setrlimit(libc::RLIMIT_DATA, &r);
                    }
                }
                Ok(())
            };
            return unsafe { self.pre_exec(func) };
        }
        self
    }

    fn setsid(&mut self) -> &mut Self {
        let func = move || {
            unsafe {
                libc::setsid();
            };
            Ok(())
        };
        unsafe { self.pre_exec(func) }
    }

    fn core_limit(&mut self) -> &mut Self {
        let func = move || {
            let r0 = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            unsafe {
                libc::setrlimit(libc::RLIMIT_CORE, &r0);
            };
            Ok(())
        };
        unsafe { self.pre_exec(func) }
    }

    fn net_isolate(&mut self) -> &mut Self {
        #[cfg(target_os = "linux")]
        {
            let func = move || {
                use nix::sched::{unshare, CloneFlags};
                
                let flags = CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET;
                
                if let Err(_e) = unshare(flags) {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            };
            unsafe { self.pre_exec(func) }
        }
        #[cfg(not(target_os = "linux"))]
        {
            self
        }
    }
}

#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(target_os = "windows")]
impl SetLimit for Command {
    fn mem_limit(&mut self, _size: Option<u64>) -> &mut Self {
        self
    }

    fn setsid(&mut self) -> &mut Self {
        self
    }

    fn core_limit(&mut self) -> &mut Self {
        self
    }

    fn net_isolate(&mut self) -> &mut Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    /// Spawn `curl --connect-timeout 2 http://1.1.1.1` with or without
    /// `net_isolate()`.  Returns the process exit code.
    ///
    /// curl exit code 7 = "Failed to connect to host" (network unreachable).
    /// curl exit code 0 = successful HTTP response.
    #[cfg(target_os = "linux")]
    fn curl_exit_code(isolate: bool) -> i32 {
        let mut cmd = Command::new("curl");
        cmd.args([
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--connect-timeout",
                "2",
                "http://1.1.1.1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if isolate {
            cmd.net_isolate();
        }
        let output = cmd.output().expect("failed to spawn curl");
        output.status.code().unwrap_or(-1)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_net_isolate_blocks_tcp_connect() {
        let code = curl_exit_code(true);
        // curl exit code 7 = couldn't connect to host (network unreachable
        // inside the isolated network namespace).
        assert_eq!(
            code, 7,
            "net_isolate should make curl fail to connect (exit 7), got exit {code}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_without_net_isolate_tcp_connect_allowed() {
        let code = curl_exit_code(false);
        // Without isolation curl should succeed (exit 0) — we can reach 1.1.1.1.
        assert_eq!(
            code, 0,
            "curl should succeed without net_isolate (exit 0), got exit {code}"
        );
    }
}
