/// Generator for replay mutating and generating.
/// ./bin/hopper-generator ./crashes/id:000000
/// if function target should be specific, set `HOPPER_PATTERN` environment.
///
use hopper::{
    Deserialize, Deserializer, FuzzProgram, FuzzStmt, MutateOperator, RngState,
    Serialize
};

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    hopper_harness::hopper_extend();
    flexi_logger::Logger::try_with_env_or_str("trace")?.start()?;
    if let Some(file) = std::env::args().nth(1) {
        let mut replay_mode = true;
        let mut op_mode = false;
        let mut input_only = false;
        let mut refine = false;
        std::env::args().for_each(|flag| {
            if flag == "--op-mode" {
                op_mode = true;
            }
            if flag == "--no-replay-mode" {
                replay_mode = false;
            }
            if flag == "--input-only" {
                input_only = true;
            }
            if flag == "--refine" {
                refine = true;
            }
        });
        process_file(&file, op_mode, replay_mode, input_only, refine)?;
    }
    Ok(())
}

fn process_file(
    file: &str,
    op_mode: bool,
    replay_mode: bool,
    input_only: bool,
    refine: bool,
) -> eyre::Result<()> {
    hopper::init_constraints()?;
    hopper::read_existing_opaue()?;

    hopper::effective::load_effective_args()?;
    let buf = std::fs::read_to_string(file)?;
    if refine {
        let mut program = hopper::read_program(&buf, false)?;
        program.refine_program()?;
        log::info!("refined program:\n {}", program.serialize_all()?);
        return Ok(());
    }

    let mut lines = buf.lines();
    let mut parent = None;
    if let Some(l) = lines.next() {
        let mut de = Deserializer::new(l, None);
        let _ = de.next_token_until("Parent:")?;
        let parent_buf = de.next_token_until(",")?;
        if parent_buf != "None" {
            parent = Some(parent_buf.parse::<usize>()?);
        }
        log::info!("parent: {:?}", parent);
    }

    let mut rng_state = None;
    for l in lines {
        let mut de = Deserializer::new(l, None);
        if de.strip_token("<RNG>") && replay_mode {
            de.trim_start();
            log::info!("load rng : {}", l);
            rng_state = Some(RngState::deserialize(&mut de)?);
        }
        if de.strip_token("<FLAG>") {
            de.trim_start();
            let flag: u8 = de.parse_number()?;
            hopper::set_mutate_flag(flag);
        }
        if let Some(pos) = l.find(hopper::CallStmt::TARGET) {
            let f = l[pos + 9..].split_once(' ').unwrap().0;
            hopper::get_config_mut().set_func_target(f)?;
        }
        if de.strip_token("<OP>") && op_mode {
            if let Some(seed_id) = parent {
                let mut program = hopper::read_input_in_queue(seed_id)?;
                program.parent = Some(seed_id);
                de.trim_start();
                de.program = Some(&mut program);
                let operators = Vec::<MutateOperator>::deserialize(&mut de)?;
                log::info!("ops: {}", operators.serialize()?);
                program.mutate_program_by_ops(&operators)?;
                program.refine_program()?;
                log::info!("mutate program:\n {}", program.serialize_all()?);
                return Ok(());
            } else {
                return Err(eyre::eyre!(
                    "Program parent not found. operator mode require a parent to be mutated"
                ));
            }
        }
    }

    if op_mode {
        return Err(eyre::eyre!("Operators not found."));
    }

    if let Ok(pattern) = std::env::var("FUNC_PATTERN") {
        let config = hopper::get_config_mut();
        config.func_pattern = Some(pattern);
        config.set_func_pattern()?;
    }
    if let Ok(v) = std::env::var("PILOT_DET") {
        hopper::set_pilot_det(v != "0" && v != "false");
    }
    if let Ok(v) = std::env::var("SINGLE_CALL") {
        hopper::set_single_call(v != "0" && v != "false");
    }
    if let Ok(v) = std::env::var("REUSE_STMT") {
        hopper::set_reuse_stmt(v != "0" && v != "false");
    }

    if let Some(seed_id) = parent {
        let mut program = hopper::read_input_in_queue(seed_id)?;
        program.parent = Some(seed_id);
        program.update_weight();
        // do not support det mutate
        for is in &mut program.stmts {
            if let FuzzStmt::Load(load) = &mut is.stmt {
                load.state.done_deterministic();
            }
        }
        if let Some(rng) = rng_state {
            hopper::restore_rng_state(rng);
        }
        log::info!("parent: {}", program.serialize_all()?);
        if input_only {
            program.mutate_program_inputs()?;
        } else {
            log::info!("current rng2: {:?}", hopper::save_rng_state());
            program.mutate_program()?;
        }
        log::info!("mutate program:\n {}", program.serialize_all()?);
    } else {
        if let Some(rng) = rng_state {
            hopper::restore_rng_state(rng);
        }
        let target = hopper::get_config().func_target.unwrap();
        let program = FuzzProgram::generate_program_for_func(target)?;
        log::info!("generate program:\n{}", program.serialize_all()?);
    }

    Ok(())
}
