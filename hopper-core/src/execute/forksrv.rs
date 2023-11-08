use std::{
    io::{prelude::*, BufReader, BufWriter},
    path::PathBuf,
    time::Duration,
};

use super::*;
use crate::{config, feedback::*, runtime::*, HopperError, TimeUsage};
use eyre::Context;

pub struct ForkSrv {
    pub reader: BufReader<UnixStream>,
    pub writer: BufWriter<UnixStream>,
    pub feedback: Feedback,
    pub timeout_limit: Duration,
}

impl ForkSrv {
    pub fn new() -> eyre::Result<Self> {
        crate::log!(info, "start fork server...");
        #[cfg(target_os = "windows")]
        crate::execute::bind_cpu_win()?;
        let timeout_limit = Self::timeout_limit()?;
        let socket = Self::connect_socket(&timeout_limit)?;
        let _ = config::get_api_sensitive_cov();
        Ok(Self {
            reader: BufReader::new(socket.try_clone()?),
            writer: BufWriter::new(socket),
            feedback: Feedback::new()?,
            timeout_limit,
        })
    }

    fn timeout_limit() -> eyre::Result<Duration> {
        let timeout_setting =
            std::env::var(config::TIMEOUT_LIMIT_VAR).unwrap_or_else(|_| "1".to_string());
        let timeout_limit = Duration::from_secs(timeout_setting.parse()?);
        crate::log!(trace, "forksrv timeout: {timeout_limit:?}");
        Ok(timeout_limit)
    }

    fn connect_socket(_timeout_limit: &Duration) -> eyre::Result<UnixStream> {
        let socket_path = PathBuf::from(std::env::var(config::FORK_SOCKET_PATH)?);
        let socket = UnixStream::connect(socket_path)?;
        // Do not set timeout now
        // socket.set_read_timeout(Some(timeout_limit.saturating_add(Duration::from_secs(5))))?;
        // socket.set_write_timeout(Some(timeout_limit.saturating_add(Duration::from_secs(5))))?;
        Ok(socket)
    }

    pub fn fork_loop(&mut self) -> eyre::Result<()> {
        #[cfg(target_os = "windows")]
        if crate::check_hopper_use_thread_win() {
            return self.thread_loop_win();
        }
        let mut executor = super::Executor::default();
        executor.set_timeout(self.timeout_limit);
        let mut exec_usage = TimeUsage::default();
        let start_at = std::time::Instant::now();
        disable_coverage_feedback();
        let timeout_limit = self.timeout_limit;
        let loop_num = config::get_fast_execute_loop();
        crate::log!(info, "start fork loop !");
        loop {
            let cmd = self.receive_cmd()?;
            match cmd {
                ForkCmd::Execute => {
                    crate::log!(debug, "receive {}-th program..", executor.count());
                    let buf = self.read_buf()?;
                    crate::log!(debug, "program: {}", buf);
                    self.feedback.clear();
                    let status = {
                        let _counter = exec_usage.count();
                        executor.execute(|| {
                            let mut program = self.read_program(&buf)?;
                            // std::mem::forget(program.stmts);
                            program.eval()
                        })
                    };
                    crate::log!(debug, "status: {:?}", status);
                    writeln!(self.writer, "{}", status.serialize()?)?;
                    self.writer.flush()?;
                }
                ForkCmd::Loop => {
                    crate::log!(debug, "receive {}-loop program (fast)..", executor.count());
                    executor.set_timeout(Duration::from_secs(3600)); // long enough
                    let mut buf = self.read_buf()?;
                    let status = {
                        let _counter = exec_usage.count();
                        executor.execute(|| {
                            for i in 0..loop_num {
                                if i > 0 {
                                    let cmd = self.receive_cmd()?;
                                    crate::log!(debug, "receive : {cmd:?}");
                                    if cmd != ForkCmd::Loop {
                                        break;
                                    }
                                    buf = self.read_buf()?;
                                }
                                crate::log!(debug, "receive {i}-th program in loop (fast)..");
                                crate::log!(debug, "program: {}", buf);
                                self.feedback.clear();
                                self.feedback.instrs.loop_cnt = i as u32;
                                // std::mem::forget(program.stmts);
                                // std::sync::atomic::compiler_fence( std::sync::atomic::Ordering::SeqCst);
                                let mut program = self.read_program(&buf)?;
                                // std::sync::atomic::compiler_fence( std::sync::atomic::Ordering::SeqCst);
                                let (sender, receiver) = std::sync::mpsc::channel();
                                let _ = std::thread::Builder::new().spawn(move || {
                                    if receiver.recv_timeout(timeout_limit).is_err() {
                                        std::process::exit(config::TIMEOUT_CODE);
                                    }
                                });

                                let ret = program.eval();
                                let _ = sender.send(true);
                                let status = if let Err(e) = ret {
                                    if let Some(he) = e.downcast_ref::<crate::HopperError>() {
                                        match he {
                                            HopperError::DoubleFree { .. } => StatusType::Crash {
                                                signal: super::Signal::SIGABRT,
                                            },
                                            HopperError::AssertError{ msg: _, silent } => {
                                                if *silent {
                                                    StatusType::default()
                                                } else {
                                                    StatusType::Crash { signal: super::Signal::SIGABRT }
                                                }
                                            },
                                            HopperError::UseAfterFree { .. } => {
                                                StatusType::default()
                                            }
                                            _ => StatusType::Ignore,
                                        }
                                    } else {
                                        StatusType::Ignore
                                    }
                                } else {
                                    StatusType::Normal
                                };
                                crate::log!(debug, "loop status(inner): {:?}", status);
                                if i + 1 >= loop_num {
                                    writeln!(self.writer, "{}", StatusType::LoopEnd.serialize()?)?;
                                    crate::log!(debug, "loop is going to finish!");
                                }
                                writeln!(self.writer, "{}", status.serialize()?)?;
                                self.writer.flush()?;
                                canary::clear_canary_protection();
                                self.feedback.instrs.loop_cnt = i as u32 + 1;
                                // break if we find some errors
                                if !status.is_normal() {
                                    break;
                                }
                            }
                            crate::log!(debug, "loop has finished");
                            self.feedback.instrs.loop_cnt = loop_num as u32;
                            Ok(())
                        })
                    };

                    crate::log!(debug, "loop status(outer): {:?}", status);
                    let executed_loop = { self.feedback.instrs.loop_cnt };
                    crate::log!(info, "executed loop: {executed_loop}, status: {status:?}");
                    writeln!(self.writer, "{}", status.serialize()?)?;
                    self.writer.flush()?;
                    executor.set_timeout(timeout_limit);
                }
                ForkCmd::Review => {
                    crate::log!(
                        debug,
                        "receive {}-th program for review..",
                        executor.count()
                    );
                    let buf = self.read_buf()?;
                    crate::log!(debug, "program: {}", buf);
                    self.feedback.clear();
                    // make timeout longer
                    executor.set_timeout(self.timeout_limit * 3);
                    let status = {
                        let _counter = exec_usage.count();
                        executor.execute(|| {
                            let mut program = self.read_program(&buf)?;
                            program.review()
                        })
                    };
                    executor.set_timeout(self.timeout_limit);
                    crate::log!(debug, "review status: {:?}", status);
                    writeln!(self.writer, "{}", status.serialize()?)?;
                    self.writer.flush()?;
                }
                ForkCmd::Sanitize => {
                    crate::log!(
                        debug,
                        "receive {}-th program for sanitize..",
                        executor.count()
                    );
                    let buf = self.read_buf()?;
                    self.feedback.clear();
                    let status = {
                        let _counter = exec_usage.count();
                        executor.execute(|| {
                            let mut program = self.read_program(&buf)?;
                            program.sanitize()
                        })
                    };
                    executor.set_timeout(self.timeout_limit);
                    crate::log!(debug, "sanitize status: {:?}", status);
                    writeln!(self.writer, "{}", status.serialize()?)?;
                    self.writer.flush()?;
                }
                ForkCmd::Config(config) => {
                    crate::log!(info, "receive config: {config}");
                    if let Some(pos) = config.find('=') {
                        let key = &config[..pos];
                        let value = &config[pos + 1..];
                        if key == OPAQUE_CONFIG_KEY {
                            let list: Vec<&str> = value.split(',').collect();
                            for item in list {
                                global_gadgets::get_mut_instance().add_opaque_type(item);
                            }
                        }
                    }
                    // ping the client that we have received.
                    writeln!(self.writer, "{}", StatusType::Ignore.serialize()?)?;
                    self.writer.flush()?;
                }
                ForkCmd::Finish => {
                    crate::log!(warn, "break server loop");
                    let all_secs = start_at.elapsed().as_secs();
                    crate::log!(
                        info,
                        "Time uasge : exec {}({}) - {} ",
                        crate::utils::format_count(all_secs as usize),
                        exec_usage.percent(all_secs),
                        exec_usage.avg_ms()
                    );
                    break;
                }
            }
        }
        Ok(())
    }

    fn receive_cmd(&mut self) -> eyre::Result<ForkCmd> {
        match io_utils::receive_line(&mut self.reader) {
            Ok(cmd) => Ok(cmd),
            Err(err) => {
                if let Some(HopperError::ReadLineEOF) = err.downcast_ref::<HopperError>() {
                    return Err(err);
                }
                // The fork trick copys the socket we used for comunications.
                // since we use it both in the parent and child,
                // the socket may be inconsistent after some unpected exits.
                // so we should clear the buffer in socket manually.
                crate::log!(warn, "try to cosume the remain program, err: {}", err);
                let buf = self.read_buf().context("fail to cosume buffer")?;
                crate::log!(info, "ignore buf: {buf}");
                io_utils::receive_line(&mut self.reader).context("fail to receive cmd")
            }
        }
    }

    pub fn read_buf(&mut self) -> eyre::Result<String> {
        let mut buf = String::new();
        loop {
            let n = self
                .reader
                .read_line(&mut buf)
                .context("fail to read line")?;
            if n == 6 && buf.ends_with("<END>\n") {
                break;
            }
        }
        Ok(buf)
    }

    pub fn read_program(&mut self, buf: &str) -> eyre::Result<FuzzProgram> {
        let read_result = { read_program(buf, config::USE_CANARY) };
        let program = match read_result {
            Ok(p) => p,
            Err(e) => {
                writeln!(
                    self.writer,
                    "fork server error, detailed message is wrote into misc/harness_error.log"
                )?;
                let path = crate::config::output_file_path("misc/harness_error.log");
                let mut f = std::fs::File::create(path)?;
                writeln!(f, "program: {buf}")?;
                writeln!(f, "{e:#?}")?;
                eyre::bail!(e);
            }
        };
        Ok(program)
    }
}
