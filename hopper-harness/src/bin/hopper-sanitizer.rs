use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::{Context, ContextCompat};
use hopper::{
    self, filter_function_constraint_with, ConstraintSig, Deserialize, FuzzStmt,
    Fuzzer, RcIndex, SanitizeResult, Serialize,
};

pub fn main() -> eyre::Result<()> {
    flexi_logger::Logger::try_with_env_or_str("info")?.start()?;
    hopper_harness::hopper_extend();
    hopper::log!(info, "read constraints...");
    let mut fuzzer = hopper::create_fuzzer()?;

    if let Some(file_name) = std::env::args().nth(1) {
        let path = PathBuf::from(file_name);
        sanitize_crash(&path, &mut fuzzer, None, 0, 1)?;
        return Ok(());
    }

    let minimized_crashes_dir = hopper::output_file_path(hopper::MINIMIZED_CRASHES_DIR);
    if minimized_crashes_dir.exists() {
        std::fs::remove_dir_all(&minimized_crashes_dir)?;
    }
    std::fs::create_dir(minimized_crashes_dir)?;

    let crashes = fuzzer
        .depot
        .crashes
        .read_dir()?
        .iter()
        .filter(|x| x.extension().is_none())
        .cloned()
        .collect();
    let crashes = sanitize_crash_by_rip(crashes)?;
    let crashes = sanitize_grouped_crashes(crashes, &mut fuzzer)?;
    let crashes = sanitize_crash_by_clang_sanitizer_pc(crashes)?;
    let crashes = sanitize_variable_args_crash(crashes)?;
    sanitize_uninfered_crashes(&crashes, &mut fuzzer)?;
    classify_crashes_by_infer(&crashes)?;
    Ok(())
}

// Remove the duplicated crashes by rip, and save results in unique_crashes.
fn sanitize_crash_by_rip(crashes: Vec<PathBuf>) -> eyre::Result<Vec<PathBuf>> {
    hopper::log!(info, "Remove the duplicated crashes by rip..");
    let mut unique_programs: Vec<PathBuf> = Vec::new();
    let mut rip_set: HashSet<String> = HashSet::new();
    for crash_path in &crashes {
        let crash_raw = std::fs::read_to_string(crash_path)
            .with_context(|| format!("fail to read this path : {crash_path:?} to string."))?;
        let rip = extract_program_rip(&crash_raw);
        if let Some(rip) = rip {
            if rip_set.contains(&rip) {
                hopper::log!(warn, "duplicated crash filtered out by rip: {}", rip);
                continue;
            }
            // rip == "0x0" may be many different cases
            if rip != "0x0" {
                rip_set.insert(rip);
            }
        }
        unique_programs.push(crash_path.clone());
    }
    hopper::log!(
        info,
        "sanitize {} crashes to : {} by rip",
        crashes.len(),
        unique_programs.len()
    );
    Ok(unique_programs)
}

// remove the duplicated crashes by pc of clang sanitizer.
fn sanitize_crash_by_clang_sanitizer_pc(crashes: Vec<PathBuf>) -> eyre::Result<Vec<PathBuf>> {
    hopper::log!(info, "Remove the duplicated crashes by pc of clang sanitizer..");
    let mut fail_cnt = 0;
    let mut unique_programs: Vec<PathBuf> = Vec::new();
    let mut pc_set: HashSet<String> = HashSet::new();
    for crash_path in &crashes {
        let mut executable_path = PathBuf::from(crash_path);
        executable_path.set_extension("out");
        if !executable_path.exists() {
            fail_cnt += 1;
            continue;
        }
        // hopper::log!(info, "{:?}", executable_path);
        let hopper_out_dir = hopper::OUTPUT_DIR;
        let binary = String::from(executable_path.to_str().context("path should be valid")?);
        //let binary = String::from(".") + &binary;
        let output = Command::new("setarch")
            .arg("-R")
            .arg(binary)
            .env("LD_LIBRARY_PATH", hopper_out_dir)
            .output()
            .context("fail to execute the program")?;
        let err_output = String::from_utf8_lossy(&output.stderr);
        if let Some(pc) =  extract_output_pc(&err_output) {
            if pc_set.contains(&pc) {
                hopper::log!(warn, "duplicated crash filtered out by pc: {}", pc);
            } else {
                unique_programs.push(crash_path.clone());
                pc_set.insert(pc);
            }
            continue;
        }
        unique_programs.push(crash_path.clone());
        hopper::log!(info, "not found a valid pc from this: {:#?}", err_output);
    }
    if fail_cnt == crashes.len() {
        hopper::log!(warn, "skip duplicated cashes by clang sanitizer!");
        hopper::log!(warn, "please make sure your program are translated and compiled with AddressSanitizer correctly. hint: ./fuzz.sh hopper translate_crash");
        return Ok(crashes);
    }
    hopper::log!(
        info,
        "sanitize {} crashes to : {} by sanitizing pc",
        crashes.len(),
        unique_programs.len()
    );
    Ok(unique_programs)
}

fn sanitize_crash(
    crash_path: &Path,
    fuzzer: &mut Fuzzer,
    minimized_crashes_holder: Option<&hopper::DepotDir>,
    crash_index: usize,
    total: usize,
) -> eyre::Result<bool> {
    let crash_raw = std::fs::read_to_string(crash_path)?;
    let mut crash_p = hopper::read_program(&crash_raw, false)?;
    hopper::parse_program_extra(&crash_raw, &mut crash_p)?;
    hopper::log!(info, "[{crash_index}/{total}]:id_{:06}", crash_p.id);

    // check
    // 1. its ops is likely to FP
    // 2. whether it violates the constraint
    // 3. whether it is from another seed or succeeded in pilot
    // check ops

    if let Some(fail_at) = crash_p.get_fail_stmt_index() {
        crash_p.stmts.truncate(fail_at.get() + 1);
        crash_p.check_ref_use()?;
        hopper::log!(info, "minimized program: {}", crash_p.serialize()?);
    }
    // Refine the program again to see if it violates the latest constraint
    let mut refine_ops = crash_p.refine_program()?;
    // Eliminate invalidated ops
    /*
    let constraint_violated = refine_ops.iter().any(|op| {
        matches!(op.op, hopper::MutateOperation::PointerGen { .. })
            || matches!(op.op, hopper::MutateOperation::InitOpaque { .. })
    });
    */
    if !refine_ops.is_empty() {
        let status = fuzzer.executor.execute_program(&crash_p)?;
        if status.is_normal() {
            refine_ops.retain(|op| !op.key.is_released());
            hopper::log!(
                warn,
                "violate constraints! ops: {}",
                refine_ops.serialize()?
            );
            return Ok(false);
        }
    }

    let mut failed_holder = None;
    for st in crash_p.stmts.iter() {
        if let hopper::FuzzStmt::Call(call) = &st.stmt {
            if call.failure {
                failed_holder = Some((st.index.get(), call.fg.f_name.to_owned()));
                break;
            }
        }
    }

    if let Some((failed_at, failed_func_name)) = failed_holder {
        if !filter_function_constraint_with(&failed_func_name, |c| c.can_succeed) {
            hopper::log!(warn, "crash function is pilot-infer failed!");
            return Ok(false);
        }

        // double check if it is crash
        let mut num_fail = 0;
        // hopper::log!(info, "re-check execution");
        for _ in 0..10 {
            let status = fuzzer.executor.execute_program(&crash_p)?;
            if status.is_crash() {
                num_fail += 1;
            }
        }
        if num_fail < 10 {
            hopper::log!(
                info,
                "the program may success during re-running, {num_fail}/10"
            );
        }
        if num_fail == 0 {
            hopper::log!(info, "double check crash fail: the program runs successful");
            return Ok(false);
        }

        let skip_mutate = std::env::var("SKIP_MUTATE").is_ok();
        let mut succ_cnt = 0;
        if !skip_mutate {
            // try mutate the crash for 30 times and see how many times it succeeds
            // hopper::log!(info, "mutate input");
            crash_p.update_weight();
            for is in &mut crash_p.stmts {
                if let FuzzStmt::Load(load) = &mut is.stmt {
                    load.state.done_deterministic();
                }
            }
            let max = 10 * crash_p.stmts.len();
            for _ in 0..max {
                let mut cloned_p = crash_p.clone();
                cloned_p.mutate_program_inputs()?;
                let status = fuzzer.executor.execute_program(&cloned_p)?;
                let last_index = fuzzer.observer.feedback.last_stmt_index();
                let is_effective_exec = last_index >= failed_at;
                if status.is_normal() && is_effective_exec {
                    succ_cnt += 1;
                    hopper::log!(warn, "the input can be success after mutate input");
                    break;
                }
            }
            if succ_cnt == 0 {
                hopper::log!(
                    warn,
                    "crash input always crash after mutate values in input"
                );
            }
        }
        if skip_mutate || succ_cnt >= 0 {
            let mut cov_p = crash_p.clone();
            cov_p.set_calls_track_cov(false);
            cov_p.get_call_stmt_mut(failed_at).unwrap().track_cov = true;
            let status = fuzzer.executor.execute_program(&cov_p)?;
            if status.is_normal() {
                hopper::log!(error, "status should not be normal");
            }
            let path = fuzzer.observer.feedback.path.get_list();
            hopper::log!(debug, "path: {:?}", path);
            let new_edges = fuzzer.observer.get_new_uniq_path(status);
            if !new_edges.is_empty() {
                hopper::log!(info, "found new edges, start sanitize");
                fuzzer.executor.sanitize_program(&crash_p)?;
                let sanitize_result = SanitizeResult::conclusion(&crash_p)?;
                hopper::log!(debug, "new edges: {:?}", new_edges);
                fuzzer.observer.merge_coverage(&new_edges, status);
                let file_name = crash_path.file_name().unwrap().to_str().unwrap();
                if let Some(minimized_crashes) = minimized_crashes_holder {
                    hopper::log!(info, "save {file_name} into minimized_dir.");
                    minimized_crashes.save_program_custom(
                        file_name,
                        &crash_p,
                        status,
                        Some(sanitize_result.to_string()),
                    )?;
                } else {
                    hopper::log!(info, "Accepted.");
                }

                // minimize
                let mut min_p = crash_p.clone();
                // truncate stmts
                min_p.set_calls_track_cov(false);
                let mut has_min = false;
                if let Some(crash_pos) = min_p.get_fail_stmt_index() {
                    if let Some(call) = min_p.get_call_stmt_mut(crash_pos.get()) {
                        eyre::ensure!(call.failure, "should be failure");
                        call.ident = hopper::CallStmt::TARGET.to_string();
                        call.track_cov = true;
                    }
                    let new_len = crash_pos.get() + 1;
                    if new_len < min_p.stmts.len() {
                        has_min = true;
                    }
                    min_p.stmts.truncate(new_len);
                    min_p.check_ref_use()?;
                }
                if fuzzer.minimize(&mut min_p, &status)? {
                    has_min = true;
                }
                if has_min {
                    hopper::log!(info, "found minimized crash input");
                    let min_file_name = format!("{file_name}_min");
                    let min_sanitize_result = SanitizeResult::conclusion(&min_p)?;
                    if let Some(minimized_crashes) = minimized_crashes_holder {
                        minimized_crashes.save_program_custom(
                            &min_file_name,
                            &min_p,
                            status,
                            Some(min_sanitize_result.to_string()),
                        )?;
                    } else {
                        hopper::log!(info, "minimized program: {}", min_p.serialize_all()?);
                        hopper::log!(info, "sanitizer: {}", min_sanitize_result.to_string());
                    }
                }
                return Ok(true);
            } else {
                hopper::log!(warn, "duplicated crash");
            }
        }
    } else {
        hopper::log!(
            warn,
            "failed at non-call statement: {}",
            crash_p.serialize()?
        );
    }
    Ok(false)
}


pub fn extract_program_rip(buf: &str) -> Option<String> {
    //memory 0x402000 and RIP 0x7fc72eff3bb6
    let re = regex::Regex::new(r"0x\d+ and RIP (0x[0-9a-z]+) ").unwrap();
    let res = re.captures(buf);
    if let Some(cap) = res {
        let rip = cap.get(1);
        if let Some(rip) = rip {
            return Some(rip.as_str().to_string());
        }
    }
    None
}

pub fn extract_output_pc(buf: &str) -> Option<String> {
    let re = regex::Regex::new(r"pc (0x[0-9a-z]+) ").unwrap();
    let res = re.captures(buf);
    if let Some(cap) = res {
        let pc = cap.get(1);
        if let Some(pc) = pc {
            return Some(pc.as_str().to_string());
        }
    }
    None
}

/// extract violate constraints from raw str program.
pub fn extract_violate_constraints(buf: &str) -> eyre::Result<Vec<ConstraintSig>> {
    //* Voilate constraint: png_convert_to_rfc1123_buffer[$0][[&]] = SetLength${ len: 4,  }, png_convert_to_rfc1123_buffer[$0][[&]] = SetLength${ len: 64,  },
    let mut constraint_vec: Vec<ConstraintSig> = Vec::new();
    let mut buf_de = hopper::Deserializer::new(buf, None);
    if buf_de.next_token_until("Violate constraint: ").is_err() {
        return Ok(constraint_vec);
    }
    while buf_de.peek_char().is_some() {
        let curr_buf = buf_de.buf;
        let mut i = 0;
        let mut bracket_cnt = 0;
        while i < curr_buf.len() {
            if let Some(c) = curr_buf.chars().nth(i) {
                if c == '{' {
                    bracket_cnt += 1;
                } else if c == '}' {
                    bracket_cnt -= 1;
                } else if c == ',' && bracket_cnt == 0 {
                    break;
                }
            }
            i += 1;
        }
        let constraint_str = &curr_buf[0..i];
        buf_de.buf = curr_buf[i + 1..].trim();
        let mut de = hopper::Deserializer::new(constraint_str, None);
        let constraint_sig = hopper::ConstraintSig::deserialize(&mut de)?;
        constraint_vec.push(constraint_sig);
    }
    Ok(constraint_vec)
}

/// classify crashes into the "infered" and "uninfered" groups, according whether they have infered violate constraints.
fn classify_crashes_by_infer(crashes: &Vec<PathBuf>) -> eyre::Result<()> {
    hopper::log!(info, "Save crashes to minimized crashes directory ..."); 
    let infered_dir = hopper::output_file_path(hopper::MINIMIZED_CRASHES_DIR).join("infered");
    if !infered_dir.exists() {
        std::fs::create_dir(&infered_dir)?;
    }
    let uninfered_dir = hopper::output_file_path(hopper::MINIMIZED_CRASHES_DIR);
    let mut infered_crashes: Vec<PathBuf> = Vec::new();
    let mut uninfered_crashes: Vec<PathBuf> = Vec::new();
    for crash_path in crashes {
        hopper::log!(trace, "current path: {:?}", crash_path);
        let crash_raw = std::fs::read_to_string(crash_path)
            .unwrap_or_else(|_| panic!("fail to read this path : {crash_path:?} to string."));
        let constraint_sigs = extract_violate_constraints(&crash_raw)?;
        if constraint_sigs.is_empty() {
            uninfered_crashes.push(crash_path.clone());
        } else {
            infered_crashes.push(crash_path.clone());
        }
    }
    save_crashes_to_dir(&infered_crashes, infered_dir)?;
    save_crashes_to_dir(&uninfered_crashes, uninfered_dir)?;
    hopper::log!(
        info,
        "classify {} crashes into: {} infered and {} uninfered",
        crashes.len(),
        infered_crashes.len(),
        uninfered_crashes.len()
    );
    Ok(())
}

/// group crashed by failed functions.
fn group_crashes_by_failed_call(
    crashes: &Vec<PathBuf>,
) -> eyre::Result<HashMap<String, Vec<PathBuf>>> {
    let mut grouped_crash: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for crash_path in crashes {
        hopper::log!(trace, "{:?}", crash_path);
        let raw_program = std::fs::read_to_string(crash_path)?;
        let program = hopper::read_program(&raw_program, false)?;
        let fail_at = program.get_fail_stmt_index();
        if let Some(fail_at) = fail_at {
            if let Some(call) = program.get_call_stmt(fail_at.get()) {
                let call_name = &call.name;
                if let Some(g) = grouped_crash.get_mut(call_name) {
                    g.push(crash_path.clone());
                } else {
                    grouped_crash.insert(call_name.clone(), vec![crash_path.clone()]);
                }
            } else {
                hopper::log!(error, "cannot retrieve the failed call at {:?}", fail_at);
            }
        } else {
            hopper::log!(
                error,
                "cannot find the failed call! crash_path: {:?}",
                crash_path
            );
        }
    }
    Ok(grouped_crash)
}

/// remove the duplicated crashes from crash groups.
fn sanitize_grouped_crashes(
    crashes: Vec<PathBuf>,
    fuzzer: &mut Fuzzer,
) -> eyre::Result<Vec<PathBuf>> {
    hopper::log!(info, "Remove the duplicated crashes from crash groups ..."); 
    let grouped_crashes = group_crashes_by_failed_call(&crashes)?;
    let mut unique_programs: Vec<PathBuf> = Vec::new();
    for (group, crashes) in &grouped_crashes {
        let mut trace_vec = Vec::new();
        for crash_path in crashes {
            let crash_raw = std::fs::read_to_string(crash_path)?;
            let mut crash_program = hopper::read_program(&crash_raw, false)?;
            crash_program.set_calls_track_cov(false);
            // set the fail call's track_cov
            for is in crash_program.stmts.iter_mut() {
                if let hopper::FuzzStmt::Call(call) = &mut is.stmt {
                    if &call.name == group {
                        call.track_cov = true;
                    }
                }
            }
            let _status = fuzzer.executor.execute_program(&crash_program)?;
            let path_list = fuzzer.observer.feedback.path.get_list();
            hopper::log!(trace, "this execution paths: {:?}", path_list);
            trace_vec.push((crash_path.clone(), path_list));
        }
        // select the max_len trace, if there is other has new path as it, maybe is a fresh crash.
        trace_vec.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
        let max_trace = &trace_vec[0];
        let mut trace_set: HashSet<usize> = max_trace.1.iter().map(|x| x.0).collect();
        for (crash_path, trace) in &trace_vec[1..] {
            let has_new: Vec<&(usize, hopper::BucketType)> = trace
                .iter()
                .filter(|x| !trace_set.contains(&x.0))
                .collect();
            hopper::log!(trace, "new_trace: {:?}", has_new);
            if !has_new.is_empty() {
                has_new.iter().for_each(|x| {
                    trace_set.insert(x.0);
                });
                unique_programs.push(crash_path.clone());
                continue;
            }
            hopper::log!(warn, "duplicated crashes `{crash_path:?}` found in groups {group}")
        }
        unique_programs.push(max_trace.0.clone());
    }
    let len: usize = grouped_crashes.values().map(|x| x.len()).sum();
    hopper::log!(
        info,
        "sanitize {} crashes to : {} by grouped sanitize",
        len,
        unique_programs.len()
    );
    Ok(unique_programs)
}

/// sanitize the crashes caused by variable length arugments.
fn sanitize_variable_args_crash(crashes: Vec<PathBuf>) -> eyre::Result<Vec<PathBuf>> {
    hopper::log!(info, "Sanitize the crashes caused by variable length arugments ..."); 
    let mut sanitized_programs: Vec<PathBuf> = Vec::new();
    let len = crashes.len();
    for crash_path in crashes {
        let raw_program = std::fs::read_to_string(&crash_path)?;
        let program = hopper::read_program(&raw_program, false)?;
        if let Some(call) = program.get_fail_call_stmt() {
            let type_names = call.fg.arg_types;
            let is_variadic = hopper::is_variadic_function(type_names);
            if is_variadic {
                hopper::log!(
                    warn,
                    "a crash caused by variable arguments is filtered out."
                );
                continue;
            }
        }
        sanitized_programs.push(crash_path.clone());
    }
    hopper::log!(
        info,
        "sanitize {} crashes to : {} by filtering out the variable argument crashes.",
        len,
        sanitized_programs.len()
    );
    Ok(sanitized_programs)
}

/// infer the crashes again, mainly aim to sanitize the previous uninfered (opaque pointer) crashes.
fn sanitize_uninfered_crashes(crashes: &Vec<PathBuf>, fuzzer: &mut Fuzzer) -> eyre::Result<()> {
    hopper::log!(info, "Infer the crashes again ..."); 
    for crash_path in crashes {
        let crash_raw = std::fs::read_to_string(crash_path)?;
        if !extract_violate_constraints(&crash_raw)?.is_empty() {
            continue;
        }
        let program = hopper::read_program(&crash_raw, false)?;
        // exclude those has been refined.
        /*
        {
            let mut p = program.clone();
            let ops = p.refine_program()?;
            if !ops.is_empty() {
                let mut buf = program.serialize_all()?;
                let op_content = format!("Refine by: {}", ops.serialize()?);
                buf.push_str(&op_content);
                std::fs::write(crash_path, buf)?;
                hopper::log!(warn, "{crash_path:?} is refined by :{op_content}.");
                return Ok(());
            }
        }
        */
        let new_constraints = fuzzer.crash_infer(&program).with_context(|| {
            format!("update constraint failed: {}", program.serialize().unwrap())
        })?;
        if !new_constraints.is_empty() {
            let mut sanitize_result = hopper::SanitizeResult::default();
            sanitize_result.add_violated_constraints(&new_constraints)?;
            let mut buf = program.serialize_all()?;
            buf.push_str(&sanitize_result.to_string());
            std::fs::write(crash_path, buf)?;
            hopper::log!(warn, "{:?} uninfered crash is now infered.", crash_path);
        }
    }
    Ok(())
}

fn save_crashes_to_dir(crashes: &Vec<PathBuf>, save_dir: PathBuf) -> eyre::Result<()> {
    for crash_path in crashes {
        let basename = crash_path.file_name().unwrap();
        let mut save_path = PathBuf::from(&save_dir);
        save_path.push(basename);
        let buf = std::fs::read(crash_path)?;
        std::fs::write(save_path, buf)?;
    }
    Ok(())
}
