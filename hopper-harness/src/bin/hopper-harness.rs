//! Hopper Harness
//! Create a fork server to receive control message and execute program
//!
//! Fork Server:  harness --server
//! Replay: harness [file_name] [options]
//! options:
//!   --sanitize : use `sanitize` in program, the default one is `review`
//!   --execute : use `eval` in program, the default one is `review`
//!   --nofork : do not fork a process and then execute, it will run program with fork by default

use std::path::Path;

fn init_logger(name: &str) {
    use flexi_logger::*;
    let mut output_file = FileSpec::default().basename(name);
    output_file = output_file.directory(hopper::OUTPUT_DIR);
    Logger::try_with_env_or_str("info")
        .unwrap() // Write all error, warn, and info messages
        .log_to_file(output_file)
        .format_for_files(opt_format)
        .rotate(
            // If the program runs long enough,
            Criterion::Size(1 << 30),
            Naming::Timestamps,
            Cleanup::KeepLogFiles(3),
        )
        .start()
        .unwrap();
}

pub fn main() -> eyre::Result<()> {
    hopper_harness::hopper_extend();
    let is_server = std::env::args().any(|f| f == "--server");
    if is_server {
        let is_fast = std::env::args().any(|f| f == "--fast");
        if is_fast {
            init_logger("harness_fast");
        } else {
            init_logger("harness");
        }
        let res = hopper::run_fork_server();
        if let Err(err) = res {
            log::error!("error: {}", err);
            log::error!("root cause: {:?}", err.root_cause());
            std::process::exit(hopper::FORK_ERROR_EXIT_CODE);
        }
        return Ok(());
    }
    let query_gadgets = std::env::args().any(|f| f == "--gadgets");
    if query_gadgets {
        hopper::create_dir_in_output_if_not_exist(hopper::MISC_DIR)?;
        hopper::global_gadgets::get_instance().save_gadgets_to_file()?;
        return Ok(());
    }

    if let Some(file_name) = std::env::args().nth(1) {
        color_eyre::install()?;
        flexi_logger::Logger::try_with_env_or_str("trace")
            .unwrap()
            .start()
            .unwrap();
        let infer_crash = std::env::args().any(|f| f == "--infer");
        if infer_crash {
            hopper::global_gadgets::get_mut_instance().build_arg_and_ret_graph();
            hopper::infer_crash(&file_name)?;
            let path = Path::new("found_constraints");
            hopper::CONSTRAINTS.with(|c| c.borrow().save_to_file(path))?;
            return Ok(());
        }
        let minimize_input = std::env::args().any(|f| f == "--minimize");
        if minimize_input {
            hopper::minimize_input(&file_name)?;
            return Ok(());
        }
        let mut cmd = hopper::ForkCmd::Review;
        if std::env::args().any(|f| f == "--sanitize") {
            cmd = hopper::ForkCmd::Sanitize;
        } else if std::env::args().any(|f| f == "--execute") {
            cmd = hopper::ForkCmd::Execute;
        }
        hopper::run_program(&file_name, cmd)?;
    }
    Ok(())
}
