use clap::Parser;
use hopper::{effective::*, FuzzStmt, Serialize};

/// Hopper - fuzz libraries fully automatically
/// hopper-slice is a tool for debugging slice issues
#[derive(Parser, Debug)]
#[clap(name = "hopper-slice")]
#[clap(version = "1.0.0", author = "Tencent")]
pub struct SliceConfig {
    /// Input program
    #[clap(long, value_parser)]
    pub input: String,

    /// Call index
    #[clap(long, value_parser)]
    pub index: usize,

    /// Argument position
    #[clap(long, value_parser)]
    pub arg: Option<usize>,
}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    hopper_harness::hopper_extend();
    flexi_logger::Logger::try_with_env_or_str("trace")?.start()?;
    let config = SliceConfig::parse();
    log::info!("config: {:?}", config);
    // hopper::check_gadgets().unwrap();
    let buf = std::fs::read_to_string(&config.input)?;
    let mut program = hopper::read_program(&buf, false)?;
    hopper::parse_program_extra(&buf, &mut program)?;
    let call_i = config.index;
    if let Some(arg_pos) = config.arg {
        if let FuzzStmt::Call(call) = &program.stmts[call_i].stmt {
            let p = slice_arg(&program, call, call_i, arg_pos)?;
            log::info!("sliced: {}", p.serialize().unwrap());
        }
    } else {
        hopper::Fuzzer::collect_effective_args_in_call(&program, call_i)?;
        // log_effective_args();
    }
    Ok(())
}
