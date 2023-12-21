use std::{
    collections::HashMap,
    io::{prelude::*, BufReader, BufWriter},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{compiler_fence, Ordering},
};

use super::{limit::SetLimit, *};
use crate::{config, feedback::Feedback, FuzzProgram, Serialize, TimeUsage};
use eyre::Context;

pub struct ForkCli {
    socket_path: PathBuf,
    reader: BufReader<UnixStream>,
    writer: BufWriter<UnixStream>,
    fast_io: Option<(BufReader<UnixStream>, BufWriter<UnixStream>)>,
    pub history: Vec<FuzzProgram>,
    pub usage: TimeUsage,
}

impl ForkCli {
    pub fn new(feedback: &Feedback) -> eyre::Result<Self> {
        let config = config::get_config();
        let harness = PathBuf::from(&config::OUTPUT_DIR)
            .join("bin")
            .join("hopper-harness");
        let socket_path = socket_path();
        crate::log!(info, "path: {:?}", socket_path);
        let listener = UnixListener::bind(&socket_path).unwrap();
        let mut envs = HashMap::new();
        if let Ok(log_type) = std::env::var("RUST_LOG") {
            if log_type == "trace" {
                // avoid RUST_LOG to be trace
                envs.insert("RUST_LOG", "debug".to_string());
            }
        }
        if std::env::var("ENABLE_HARNESS_TRACE_LOG").is_ok() {
            envs.insert("RUST_LOG", "trace".to_string());
        }
        envs.insert(config::PATH_SHMID_VAR, feedback.path.get_env_var());
        envs.insert(config::INSTR_SHMID_VAR, feedback.instrs.get_env_var());
        envs.insert(config::TIMEOUT_LIMIT_VAR, config.timeout_limit.to_string());
        envs.insert(
            config::FORK_SOCKET_PATH,
            socket_path.to_string_lossy().to_string(),
        );
        if let Ok(context) = std::env::var(config::API_INSENSITIVE_COV) {
            envs.insert(config::API_INSENSITIVE_COV, context);
        }
        crate::log!(info, "Run harness: {:?}, envs: {:?}", &harness, envs);
        config::create_dir_in_output_if_not_exist(config::HARNESS_WORK_DIR)?;
        let tmout = config.timeout_limit + 5;
        Command::new(&harness)
            .arg("--server")
            .envs(&envs)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .current_dir(config::output_file_path(config::HARNESS_WORK_DIR))
            .mem_limit(config.mem_limit)
            .core_limit()
            .setsid()
            .spawn()
            .context("fail to spwan fork server in fuzzer")?;
        crate::log!(info, "wait for acception..");
        // May block here if the client doesn't exist.
        let (socket, _) = listener.accept()?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(tmout)))?;
        socket.set_write_timeout(Some(std::time::Duration::from_secs(tmout)))?;
        crate::log!(info, "fork server is initialized successfully !");
        // for fast
        let mut fast_io = None;
        let num_fast_loop = config::get_fast_execute_loop();
        if num_fast_loop > 1 {
            envs.insert(config::FAST_EXECUTE_LOOP, num_fast_loop.to_string());
            Command::new(&harness)
                .arg("--server")
                .arg("--fast")
                .envs(&envs)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .current_dir(config::output_file_path(config::HARNESS_WORK_DIR))
                .mem_limit(config.mem_limit)
                .core_limit()
                .setsid()
                .spawn()
                .context("fail to spwan fork server in fuzzer")?;
            // May block here if the client doesn't exist.
            crate::log!(info, "wait for acception..");
            let (fast_socket, _) = listener.accept()?;
            fast_socket.set_read_timeout(Some(std::time::Duration::from_secs(tmout)))?;
            fast_socket.set_write_timeout(Some(std::time::Duration::from_secs(tmout)))?;
            fast_io = Some((
                BufReader::new(fast_socket.try_clone()?),
                BufWriter::new(fast_socket),
            ));
            crate::log!(info, "fast fork server is initialized successfully !");
        }
        let cli = Self {
            socket_path,
            reader: BufReader::new(socket.try_clone()?),
            writer: BufWriter::new(socket),
            fast_io,
            history: vec![],
            usage: TimeUsage::default(),
        };

        Ok(cli)
    }

    pub fn execute_program_fast(&mut self, program: &FuzzProgram) -> eyre::Result<StatusType> {
        if self.history.len() >= crate::config::get_fast_execute_loop() {
            self.history.clear();
        }
        if let Some((reader, writer)) = &mut self.fast_io {
            let t = std::time::Instant::now();
            crate::log!(trace, "start execute program (fast)..");
            compiler_fence(Ordering::SeqCst);
            writeln!(writer, "{}", ForkCmd::Loop.serialize()?)
                .context("fail to send cmd (fast)")?;
            writer
                .write_all(program.serialize()?.as_bytes())
                .context("fail to send program (fast)")?;
            writer.flush().context("fail to flush send (fast)")?;
            let mut status: StatusType = io_utils::receive_line(reader).with_context(|| {
                format!(
                    "program: {program}\n history: {}",
                    self.history.serialize().unwrap()
                )
            })?;
            compiler_fence(Ordering::SeqCst);
            crate::log!(trace, "receive status {:?} from fork server (fast)", status);
            self.usage.add_time(&t);
            if status.is_loop_end() {
                status = io_utils::receive_line(reader).with_context(|| {
                    format!(
                        "program: {program}\n history: {}",
                        self.history.serialize().unwrap()
                    )
                })?;
                // wait for outer ping for finish process
                let _: StatusType =
                    io_utils::receive_line(reader).context("stop process status")?;
                self.history.clear();
            }
            if status.is_normal() {
                self.history.push(program.clone());
            } else {
                self.history.clear();
            }
            Ok(status)
        } else {
            self.execute_program(program)
        }
    }

    pub fn execute_program(&mut self, program: &FuzzProgram) -> eyre::Result<StatusType> {
        let t = std::time::Instant::now();
        crate::log!(trace, "start execute program..");
        compiler_fence(Ordering::SeqCst);
        self.send_cmd(ForkCmd::Execute)?;
        self.send_program(program)?;
        let status = self
            .receive_status()
            .with_context(|| format!("program: {program}"))?;
        compiler_fence(Ordering::SeqCst);
        crate::log!(trace, "receive status {:?} from fork server", status);
        self.usage.add_time(&t);
        Ok(status)
    }

    pub fn review_program(&mut self, program: &FuzzProgram) -> eyre::Result<StatusType> {
        let t = std::time::Instant::now();
        crate::log!(trace, "start review program..");
        compiler_fence(Ordering::SeqCst);
        self.send_cmd(ForkCmd::Review)?;
        self.send_program(program)?;
        let status = self.receive_status()?;
        compiler_fence(Ordering::SeqCst);
        crate::log!(trace, "review status {:?} from fork server", status);
        self.usage.add_time(&t);
        Ok(status)
    }

    pub fn sanitize_program(&mut self, program: &FuzzProgram) -> eyre::Result<StatusType> {
        let t = std::time::Instant::now();
        crate::log!(trace, "start sanitizing program..");
        compiler_fence(Ordering::SeqCst);
        self.send_cmd(ForkCmd::Sanitize)?;
        self.send_program(program)?;
        let status = self.receive_status()?;
        compiler_fence(Ordering::SeqCst);
        crate::log!(trace, "sanitize status {:?} from fork server", status);
        self.usage.add_time(&t);
        Ok(status)
    }

    pub fn set_config(&mut self, key: &str, value: &str) -> eyre::Result<()> {
        self.send_cmd(ForkCmd::Config(format!("{key}={value}")))?;
        self.writer.flush().context("fail to flush set config")?;
        let _status: StatusType = self.receive_status()?;
        if let Some((reader, writer)) = &mut self.fast_io {
            writeln!(
                writer,
                "{}",
                ForkCmd::Config("nop".to_string()).serialize()?
            )
            .context("fail to send nop cmd")?;
            writer.flush().context("fail to flush set config (fast)")?;
            let _: StatusType = io_utils::receive_line(reader).context("receive config ping")?;
            writeln!(
                writer,
                "{}",
                ForkCmd::Config(format!("{key}={value}")).serialize()?
            )
            .context("fail to send nop cmd")?;
            writer.flush().context("fail to flush set config (fast)")?;
            let _: StatusType = io_utils::receive_line(reader).context("receive config ping")?;
            self.history.clear();
        }
        Ok(())
    }

    pub fn sync_all_configs(&mut self) -> eyre::Result<()> {
        let opaque_list: Vec<&str> = crate::global_gadgets::get_instance()
            .opaque_types
            .iter()
            .map(|t| t.as_str())
            .collect();
        let opaque_list = opaque_list.join(",");
        crate::log!(info, "sync opaque config: {opaque_list:?}");
        self.set_config(OPAQUE_CONFIG_KEY, &opaque_list)?;
        Ok(())
    }

    fn send_cmd(&mut self, cmd: ForkCmd) -> eyre::Result<()> {
        writeln!(self.writer, "{}", cmd.serialize()?).context("fail to send cmd")?;
        Ok(())
    }

    fn send_program(&mut self, program: &FuzzProgram) -> eyre::Result<()> {
        self.writer
            .write_all(program.serialize()?.as_bytes())
            .context("fail to send program ")?;
        self.writer.flush().context("fail to flush send")
    }

    fn receive_status(&mut self) -> eyre::Result<StatusType> {
        match io_utils::receive_line(&mut self.reader) {
            Ok(val) => Ok(val),
            Err(err) => {
                eyre::bail!("fail to receive status : {:?}", err);
            }
        }
    }
}

impl Drop for ForkCli {
    fn drop(&mut self) {
        write!(self.writer, "{}", ForkCmd::Finish.serialize().unwrap()).unwrap();
        if let Some((_, writer)) = &mut self.fast_io {
            write!(writer, "{}", ForkCmd::Finish.serialize().unwrap()).unwrap();
        }
        if self.socket_path.exists() && std::fs::remove_file(&self.socket_path).is_err() {
            crate::log!(warn, "fail to remove {:?}", self.socket_path);
        }
    }
}

fn socket_path() -> PathBuf {
    use std::time;
    let dir = std::env::temp_dir();
    let since_the_epoch = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .expect("Time went backwards");
    // dir.join("hopper")
    dir.join(format!("hopper_socket_{}", since_the_epoch.as_millis()))
}
