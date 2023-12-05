#![allow(ambiguous_glob_reexports)]

mod config;
mod depot;
mod error;
mod execute;
mod feedback;
mod fuzz;
mod fuzzer;
mod runtime;
#[cfg(feature = "slices")]
pub mod slices;
#[cfg(test)]
mod test;
mod utils;

pub use config::*;
pub use depot::*;
pub use error::*;
pub use execute::*;
pub use feedback::*;
pub use fuzz::*;
pub use fuzzer::Fuzzer;
pub use runtime::*;
pub use utils::*;

/// Do some init work for harness
fn init_harness() -> eyre::Result<()> {
    execute::install_signal_handler();
    reserve_fds();
    read_existing_opaue()?;
    add_hooks()?;
    Ok(())
}

/// Reverse some fds, so they can't be allocated by the code.
/// We can set the variables to them, and then infer constraints.
fn reserve_fds() {
    for fd in config::RESERVED_FD_MIN..=config::RESERVED_FD_MAX {
        // check fd is used or not
        if unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
            || std::io::Error::last_os_error().raw_os_error().unwrap_or(0) != libc::EBADF
        {
            continue;
        }
        // if not used, try to fill sth on it
        unsafe { libc::dup2(0, fd) };
        // crate::log!(trace, "reserve fd: {fd}");
    }
}

/// Run fork server to execute testing program
pub fn run_fork_server() -> eyre::Result<()> {
    init_harness()?;
    let mut fork_server = execute::ForkSrv::new()?;
    fork_server.fork_loop()
}

/// Run program from input file
pub fn run_program(file: &str, cmd: ForkCmd) -> eyre::Result<()> {
    init_harness()?;
    let start_at = std::time::Instant::now();
    crate::log!(info, "file: {}", file);
    let mut feedback = feedback::Feedback::new()?;
    // read
    let buf = std::fs::read_to_string(file)?;
    crate::log!(info, "program:\n{}", &buf);
    let mut program = read_program(&buf, config::USE_CANARY)?;
    feedback.clear();
    globl::disable_coverage_feedback();
    // run
    let p_start_at = std::time::Instant::now();
    let f = || match cmd {
        ForkCmd::Sanitize => {
            let ret = program.sanitize();
            if let Err(err) = &ret {
                crate::log!(error, "call error: {:?}", err);
            }
            ret
        }
        ForkCmd::Review => {
            let ret = program.review();
            if let Err(err) = &ret {
                crate::log!(error, "call error: {:?}", err);
            }
            ret
        }
        ForkCmd::Execute => {
            let start_at_inner = std::time::Instant::now();
            let ret = program.eval();
            if let Err(err) = &ret {
                crate::log!(error, "call error: {:?}", err);
            }
            crate::log!(
                trace,
                "exec time(inner): {} micro seconds",
                start_at_inner.elapsed().as_micros()
            );
            ret
        }
        _ => Ok(()),
    };
    let fork = !std::env::args().any(|f| f == "--nofork");
    if fork {
        let mut executor = execute::Executor::default();
        let timeout_setting =
            std::env::var(config::TIMEOUT_LIMIT_VAR).unwrap_or_else(|_| "1".to_string());
        let timeout_limit = std::time::Duration::from_secs(timeout_setting.parse()?);
        // crate::log!(info, "timeout setting: {:?}", timeout_limit);
        executor.set_timeout(timeout_limit);
        let status = executor.execute(f);
        crate::log!(info, "status: {:?}", status);
        if !status.is_normal() {
            crate::log!(info, "segv addr: {:#02X}", { feedback.instrs.segv_addr });
            crate::log!(info, "rip addr: {:#02X}", { feedback.instrs.rip_addr });
        }
        if let ForkCmd::Sanitize = cmd {
            let sanitize_result = SanitizeResult::conclusion(&program)?;
            crate::log!(info, "sanitize result: {:?}", sanitize_result);
        } else if let ForkCmd::Review = cmd {
            program.attach_with_review_result()?;
        }
    } else {
        let _ret = execute::Executor::execute_fn(f);
    };

    let secs = p_start_at.elapsed().as_micros();
    crate::log!(info, "exec time: {} micro seconds", secs);
    // feedback
    crate::log!(info, "last stmt index: {}", feedback.last_stmt_index());
    let path = feedback.path.get_list();
    crate::log!(info, "path: {:?}", path);
    let br = std::env::args().any(|f| f == "--br");
    if br {
        let branches = GlobalBranches::load_from_file();
        let has_new = branches.has_new(&path, execute::StatusType::default());
        crate::log!(warn, "has_new: {}", !has_new.is_empty());
    }
    let show_cmp = std::env::args().any(|f| f == "--cmp");
    if show_cmp {
        feedback.instrs.cmp_iter(None).for_each(|c|  {
            c.log_cmp()
        });
    }
    let show_mem= std::env::args().any(|f| f == "--mem");
    if show_mem {
        feedback.instrs.mem_iter().for_each(|m| crate::log_info!("mem: {m:?}"));
    }
    crate::log!(info, "cmp_len: {}", feedback.instrs.cmp_len());
    crate::log!(info, "mem_len: {}", feedback.instrs.mem_len());
    crate::log!(info, "path_len: {}", path.len());
    let secs = start_at.elapsed().as_micros();
    crate::log!(info, "whole time: {} micro seconds", secs);
    // Avoid freed objects drop again
    std::mem::forget(program.stmts);
    canary::clear_canary_protection();
    Ok(())
}

/// Run Hopper fuzzer
pub fn run_fuzzer() -> eyre::Result<()> {
    check_gadgets()?;
    let mut fuzzer = fuzzer::Fuzzer::new()?;
    fuzzer.fuzz_loop()
}

/// Check and print gadgets
fn check_gadgets() -> eyre::Result<()> {
    let gadgets = global_gadgets::get_instance();
    crate::log!(info, "gadgets: {:?}", gadgets);
    gadgets.check()
}

/// Crate a fuzzer for debuging
pub fn create_fuzzer() -> eyre::Result<fuzzer::Fuzzer> {
    let config = config::get_config_mut();
    config.timeout_limit = 1_u64;
    let fuzzer = fuzzer::Fuzzer::new()?;
    crate::init_constraints()?;
    check_gadgets()?;
    Ok(fuzzer)
}

/// expose infer crash for debug
pub fn infer_crash(file: &str) -> eyre::Result<()> {
    let mut fuzzer = create_fuzzer()?;
    let buf = std::fs::read_to_string(file)?;
    let program = crate::read_program(&buf, false)?;
    let status = fuzzer.executor.execute_program(&program)?;
    if status.is_normal() {
        let list = fuzzer.seed_infer(&program)?;
        crate::log!(info, "found constraints: {list:?}"); 
    }
    if status.is_crash() {
        let infer_length = std::env::args().any(|f| f == "--length");
        let infer_padding = std::env::args().any(|f| f == "--padding");
        if infer_length || infer_padding {
            let fail_at = program.get_fail_stmt_index().unwrap().get();
            if let Some(mut crash_sig) = crate::get_crash_sig(Some(&program)) {
                crash_sig.hash = fuzzer.observer.feedback.path.hash_trace();
                let c = if infer_length {
                    fuzzer.crash_infer_number_length(&program, fail_at, &crash_sig)?
                } else {
                    fuzzer.infer_array_length(&program, fail_at, &crash_sig)?
                };
                crate::log!(info, "found constraints: {c:?}");
            }
            return Ok(());
        }
        let list = fuzzer.crash_infer(&program)?;
        crate::log!(info, "found constraints: {list:?}");
    }
    if status.is_timeout() {
        let list = fuzzer.timeout_infer(&program)?;
        crate::log!(info, "found constraints: {list:?}");
    }
    Ok(())
}

/// expose minimize for debug
pub fn minimize_input(file: &str) -> eyre::Result<()> {
    let mut fuzzer = create_fuzzer()?;
    let buf = std::fs::read_to_string(file)?;
    let mut program = crate::read_program(&buf, false)?;
    crate::parse_program_extra(&buf, &mut program)?;
    if let Some(parent) = program.parent {
        let p = read_input_in_queue(parent)?;
        fuzzer.depot.push_queue(p, &FeedbackSummary::default())?;
    }
    let status = fuzzer.executor.execute_program(&program)?;
    let minimized = fuzzer.minimize(&mut program, &status)?;
    if minimized {
        crate::log!(info, "input is minimized");
    }
    Ok(())
}
