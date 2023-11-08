extern crate clap;
use hopper::HopperError;
use std::io::prelude::*;

fn init_logger() {
    use flexi_logger::*;

    let output_file = FileSpec::default()
        .directory(hopper::OUTPUT_DIR)
        .basename("fuzzer");

    #[cfg(not(feature = "verbose"))]
    Logger::try_with_env_or_str("info")
        .unwrap() // Write all error, warn, and info messages
        .log_to_file(output_file)
        .duplicate_to_stdout(Duplicate::Debug)
        .format_for_files(opt_format)
        .adaptive_format_for_stdout(AdaptiveFormat::Opt)
        .rotate(
            // If the program runs long enough,
            Criterion::Size(1 << 30),
            Naming::Timestamps,
            Cleanup::KeepLogFiles(3),
        )
        .start()
        .unwrap();
    
    #[cfg(feature = "verbose")]
    {
        use flexi_logger::writers::FileLogWriter;
        let status_writer = Box::new(
            FileLogWriter::builder(
                FileSpec::default()
                    .directory(hopper::OUTPUT_DIR)
                    .suppress_timestamp()
                    .basename("status"),
            ).rotate(
                Criterion::Size(1 << 30), 
                Naming::Timestamps, 
                Cleanup::KeepLogFiles(3))
            .try_build()
            .unwrap(),
        );
    
        let status_oneshot_writer = Box::new(
            FileLogWriter::builder(
                FileSpec::default()
                    .directory(hopper::OUTPUT_DIR)
                    .suppress_timestamp()
                    .basename("status_oneshot"),
            )
            .rotate(
                Criterion::Size(1),
                Naming::Numbers,
                Cleanup::KeepLogFiles(0),
            )
            .try_build()
            .unwrap(),
        );
    
        Logger::try_with_env_or_str("info")
            .unwrap() // Write all error, warn, and info messages
            .log_to_file(output_file)
            .add_writer("Status", status_writer)
            .add_writer("StatusOneShot", status_oneshot_writer)
            .duplicate_to_stdout(Duplicate::Debug)
            .format_for_files(opt_format)
            .adaptive_format_for_stdout(AdaptiveFormat::Opt)
            .rotate(
                // If the program runs long enough,
                Criterion::Size(1 << 30),
                Naming::Timestamps,
                Cleanup::KeepLogFiles(3),
            )
            .start()
            .unwrap();
    }


}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    hopper::parse_config()?;
    init_logger();
    log::info!("Hopper starting ...");
    log::info!("config: {:?}", hopper::get_config());
    hopper_harness::hopper_extend();
    let res = hopper::run_fuzzer();
    if let Err(err) = &res {
        if let Some(HopperError::TestSuccess) = err.downcast_ref::<HopperError>() {
            std::process::exit(hopper::TEST_SUCCESS_EXIT_CODE);
        }
        log::error!("fuzzer error is wrote into misc/fuzzer_error.log");
        hopper::create_dir_in_output_if_not_exist(hopper::MISC_DIR)?;
        let path = hopper::output_file_path("misc/fuzzer_error.log");
        let mut f = std::fs::File::create(path)?;
        writeln!(f, "{err:#?}")?;
    }
    log::info!("Hopper ending ...");
    res?;
    Ok(())
}
