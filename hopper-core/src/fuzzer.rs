//! Hopper fuzzer's main process,
//! it will setup the key modules, and generate and mutate inputs.

use std::{
    io::Write,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time,
};

use eyre::Context;

use crate::{config, depot::*, execute::*, feedback::*, fuzz::*, log, runtime::*, utils};

/// A really cool fuzzer
pub struct Fuzzer {
    // -- Modules --
    pub executor: ForkCli,
    pub observer: Observer,
    pub depot: Depot,
    // -- Stats --
    pub count: usize,
    running: Arc<AtomicBool>,
    rounds: usize,
    stuck: usize,
    start_at: time::Instant,
    found_abort: bool,
}

impl Fuzzer {
    /// Setup a fuzzer!
    pub fn new() -> eyre::Result<Self> {
        let observer = Observer::new()?;
        let executor = ForkCli::new(&observer.feedback)?;
        let depot = Depot::new()?;
        let running = new_running_state();
        let start_at = time::Instant::now();
        save_pid()?;
        Ok(Self {
            executor,
            observer,
            depot,
            running,
            rounds: 0,
            count: 0,
            stuck: 0,
            start_at,
            found_abort: false,
        })
    }

    /// Main fuzz loop
    pub fn fuzz_loop(&mut self) -> eyre::Result<()> {
        // --- Pilot phase ---
        // generate simple test cases for each functions, drawing skeletons of the inputs.
        // pilot does not reuse statements, and only use single call
        set_single_call(true);
        set_reuse_stmt(false);
        let is_restart = init_constraints()?;
        self.executor.sync_all_configs()?;
        if is_restart {
            // sync existing seeds first
            let _ = self.sync_depot()?;
        } else {
            // infer constraints at pilot phase
            self.pilot_infer()?;
        }
        let density = self.observer.branches_state.get_coverage_density();
        if density > 15.0 {
            log!(
                warn,
                "Density is too large (>= 15%)! Please try to increase map size !"
            );
        }

        // --- Evolution phase ---
        // randomly generate or mutates the statements, building diverse programs on the skeleton inputs.
        while self.is_running() {
            #[cfg(all(feature = "testsuite", not(test)))]
            if self.check_testing()? {
                break;
            }
            self.print_log(true);
            let has_new = if config::ENABLE_MUTATE && cond_likely(self.rounds > 2500) {
                self.mutate_round()?
            } else {
                self.generate_round()?
            };
            self.check_stuck(has_new);
            self.rounds += 1;
        }

        self.print_log(false);
        Ok(())
    }

    /// Check if the fuzzer is stuck or not.
    /// Stuck indicates that the fuzzer has found nothing after N rounds.
    /// We will set `single_call` to false , and `resuse_stmt` to true after stuck.
    fn check_stuck(&mut self, has_new: bool) {
        if has_new {
            self.stuck = 0;
        } else {
            if self.stuck > config::ROUND_STUCK_NUM && is_single_call() {
                log!(
                    info,
                    "Generate test with single call is stuck now ! Start generate multiple calls!"
                );
                set_single_call(false);
                set_reuse_stmt(true);
                enable_call_det();
            }
            self.stuck += 1;
        }
    }

    /// Pilot for specific function
    pub fn pilot_generate_func(&mut self, f_name: &str) -> eyre::Result<()> {
        log!(info, "pilot function: {f_name}");
        let mut fail_cnt = 0;
        let prev_size = self.depot.inputs.size();
        for i in 0..config::ROUND_WARM_UP_NUM {
            if !self.is_running() {
                break;
            }
            log!(trace, "{i}-th generation in pilot {f_name}");
            set_incomplete_gen(false);
            let program = FuzzProgram::generate_program_for_func(f_name)?;
            // ignore some programs
            if program.stmts.len() > config::MAX_STMTS_LEN || is_incomplete_gen() {
                continue;
            }
            let mut save = true;
            if let Some(target) = config::get_config().func_target {
                if f_name != target {
                    save = false;
                }
            }
            let (status, _) = self.run_program(&program, false, save)?;
            // We skip the seed if it is easy to become failure after mutation,
            if !status.is_normal() {
                fail_cnt += 1;
                if fail_cnt >= config::MAX_ROUND_FAIL_NUM {
                    log!(
                        warn,
                        "Pilot `{}` fail ! the func is easy to crash or hangs!",
                        f_name
                    );
                    set_function_constraint_with(f_name, |fc| fc.can_succeed = false)?;
                    break;
                }
            }
        }
        log!(
            info,
            "find {} new seeds, failed {fail_cnt} times",
            self.depot.inputs.size() - prev_size
        );
        Ok(())
    }

    /// Check testing invoking
    #[cfg(all(feature = "testsuite", not(test)))]
    fn check_testing(&self) -> eyre::Result<bool> {
        let (need_check, mut pass) = crate::check_contraints_in_testsuite();
        if need_check {
            if std::env::var("TESTSUITE_ABORT").is_ok() && !self.found_abort {
                pass = false;
            }
        } else {
            // do not need check
            pass = self.found_abort;
        }
        if pass {
            log!(warn, "Test success at {}-th round!", self.rounds);
            eyre::bail!(crate::HopperError::TestSuccess);
        } else if self.rounds >= 500 {
            log!(warn, "Test fail at {}-th round!", self.rounds);
            return Ok(true);
        }
        Ok(false)
    }

    /// Generate round
    fn generate_round(&mut self) -> eyre::Result<bool> {
        log!(debug, "start generation in round {}", self.rounds);
        let mut round_has_new = false;
        // functions that will choose to generate
        let mut candidates = None;
        // enable generate program for function failed to run.
        let mut enable_fail = false;
        // if we stuck in generate or mutate none new inputs, try to generate
        // inputs for rarely or failed targets
        if self.stuck > config::ROUND_STUCK_NUM {
            if coin() {
                // select rarely functions
                candidates = self.observer.op_stat.get_rarely_fuzz_targets();
            }
            if config::enable_gen_fail() {
                enable_fail = true;
            }
        }
        for i in 0..config::ROUND_GENERATE_NUM {
            if !self.is_running() {
                break;
            }
            log!(trace, "{i}-th generation in round {}", self.rounds);
            set_incomplete_gen(false);
            let program = FuzzProgram::generate_program(candidates.as_ref(), enable_fail)?;
            // ignore some programs
            if program.stmts.len() > config::MAX_STMTS_LEN || is_incomplete_gen() {
                continue;
            }
            let (_, has_new) = self.run_program(&program, false, true)?;
            if has_new {
                round_has_new = true;
            }
        }
        Ok(round_has_new)
    }

    /// Mutate round
    fn mutate_round(&mut self) -> eyre::Result<bool> {
        let mut round_has_new = false;
        let seed = self.depot.select_seed();
        if seed.is_none() {
            return Ok(false);
        }
        let seed = seed.unwrap();
        let mut fail_cnt = 0;
        let weight_sum = get_weight_sum(&seed.stmts);
        let mut max = config::ROUND_MUTATE_NUM;
        // if the program is simple, which does not deserve too many mutations
        if weight_sum < 20 {
            max /= 2;
        }
        let mut i = 0;
        loop {
            if !self.is_running() || i >= max {
                break;
            }
            i += 1;
            crate::log_trace!(
                "{i}-th mutation for seed {} in round {}",
                seed.id,
                self.rounds
            );
            set_incomplete_gen(false);
            let mut p = seed.clone();
            p.mutate_program()
                .with_context(|| p.serialize_all().unwrap())?;
            // skip program without mutation
            if p.ops.is_empty() || p.stmts.len() > config::MAX_STMTS_LEN || is_incomplete_gen() {
                continue;
            }
            let (status, has_new) = self.run_program(&p, false, true)?;
            if has_new {
                round_has_new = true;
                // give the seed more power if we have found something new from it.
                // if max < 3 * config::ROUND_MUTATE_NUM && !status.is_timeout() {
                //    max += config::ROUND_MUTATE_NUM;
                // }
            }
            // We skip the seed if it is easy to become failure after mutation,
            if !status.is_normal() {
                fail_cnt += 1;
                if fail_cnt >= config::MAX_ROUND_FAIL_NUM {
                    log!(debug, "the seed is easy to crash or hangs after mutation!");
                    break;
                }
            }
        }
        Ok(round_has_new)
    }

    /// Sync depot from existing files.
    fn sync_depot(&mut self) -> eyre::Result<bool> {
        let inputs = self.depot.inputs.read_dir()?;
        for f in inputs {
            if !self.is_running() {
                break;
            }
            log!(info, "sync existing inputs {:?}", f);
            let buf = std::fs::read_to_string(&f)?;
            let program = read_program(&buf, false)?;
            self.run_program(&program, true, true)?;
        }
        // do not update their coverage
        self.depot.inputs.update_size()?;
        self.depot.hangs.update_size()?;
        self.depot.crashes.update_size()?;
        if self.depot.queue.is_empty() {
            Ok(false)
        } else {
            Ok(true)
        }
    }

    /// Counting time for program' exeution
    fn count_time(&mut self, program: &FuzzProgram) -> eyre::Result<Option<u128>> {
        // try to run multiple times, to check if it stable or not
        let t_now = time::Instant::now();
        for _ in 0..config::RE_RUN_TIMES {
            let status = self.executor.execute_program_fast(program)?;
            // We do not like seeds may crash or hangs
            if !status.is_normal() {
                crate::log_warn!("fail to count time for program, status: {status:?}");
                crate::log_trace!("program: {program}");
                return Ok(None);
                // it is not fit our `fast` mode, which may affect some global states or just not stable.
            }
        }

        Ok(Some(
            t_now.elapsed().as_micros() / config::RE_RUN_TIMES as u128,
        ))
    }

    /// Run program, and save in depot if it has new feedback
    fn run_program(
        &mut self,
        program: &FuzzProgram,
        sync: bool,
        save: bool,
    ) -> eyre::Result<(StatusType, bool)> {
        log!(trace, "run #program-{}", self.count);
        log!(trace, "{}", program.serialize_all()?);
        self.count += 1;
        let status = self.executor.execute_program_fast(program)?;
        let mut has_new = false;
        if status.is_normal() {
            has_new = self.handle_new_seed(program, status, sync, save)?;
            // try to find out the relationship between op value and cmp.
            self.observer.infer_cmp(program)?;
        } else if status.is_ignore() {
            log!(warn, "program is ignore: {}", program.serialize_all()?);
        } else {
            has_new = self.handle_new_crash(program, status, sync, save)?;
        }
        self.observer.op_stat.count_ops(program, status, has_new);
        Ok((status, has_new))
    }

    pub fn handle_new_seed(
        &mut self,
        program: &FuzzProgram,
        status: StatusType,
        sync: bool,
        save: bool,
    ) -> eyre::Result<bool> {
        let new_edges = self.observer.has_new_path(status)?;
        if new_edges.is_empty() {
            return Ok(false);
        }

        // run again to check path to avoid some call in prev iteration modify environment, e.g. global variables.
        let status = self.executor.execute_program(program)?;
        self.count += 1;
        let new_edges = self.observer.has_new_path(status)?;
        if new_edges.is_empty() {
            return Ok(false);
        }
        let mut fb_summary = self.observer.summary_feedback(status);

        let start_at = std::time::Instant::now();

        // ---- initialize program that will be put on the queue
        let mut p = program.clone_without_state()?;
        eyre::ensure!(
            p.stmts.len() == program.stmts.len() || (p.parent.is_some() && p.ops.is_empty()),
            "inconsistent program: {program}"
        );
        let id = self.depot.fetch_id(status);
        p.id = id;

        // ----- infer new constraints for the seed
        if !self.seed_infer(&p)?.is_empty() {
            p.refine_program()?;
        }

        // ----- minimize input
        let _changed = self.minimize(&mut p, &status)?;
        let min_secs = start_at.elapsed().as_secs_f32();

        // ----- update coverage
        crate::log!(trace, "id: {id}, new edges: {new_edges:?}");
        self.observer.merge_coverage(&new_edges, status);

        // ----- count time for caculate speed for the seed
        let Some(time_used) = self.count_time(&p)? else {
            return Ok(true);
        };
        fb_summary.time_used = time_used;
        let count_secs = start_at.elapsed().as_secs_f32() - min_secs;

        // ----- review the program to get more information
        let status = self.executor.review_program(&p)?;

        if !status.is_normal() {
            log!(warn, "fail to review program, id: {id}");
            if save {
                self.depot.save(StatusType::Normal, &p, sync)?;
            }
        } else {
            if save {
                // save to disk
                self.depot.save(status, &p, sync)?;
            } else {
                crate::log!(warn, "skip save queue id {id}");
            }
            p.attach_with_review_result()?;
            p.update_weight();
            // collect effective arguments
            self.collect_effective_args(&p, &new_edges)?;

            // set calls to be trackable, and track 'un-track' functions
            // it should do at the end!!
            if p.set_calls_track_cov(true) {
                // update coverage if has any 'un-track' function
                log!(trace, "has un-track function, try to find new blocks.");
                let status = self.executor.execute_program(&p)?;
                self.observer
                    .update_summary(&mut fb_summary, status);
                let new_edges_all = self.observer.has_new_path(status)?;
                self.observer.merge_coverage(&new_edges_all, status);
            }
            if save {
                // save to queue
                p.parent = Some(p.id);
                p.ops.clear();
                p.rng = None;
                p.mutate_flag = 0;
                self.depot.push_queue(p, &fb_summary)?;
            }
        }

        let review_secs = start_at.elapsed().as_secs_f32() - count_secs;
        let cur_i = self.count;
        crate::log_trace!("find new input at {cur_i} , min: {min_secs}s,  count: {count_secs}, review: {review_secs}");

        Ok(true)
    }

    pub fn handle_new_crash(
        &mut self,
        program: &FuzzProgram,
        status: StatusType,
        sync: bool,
        save: bool,
    ) -> eyre::Result<bool> {
        if status.is_abort() {
            self.found_abort = true;
        }
        let mut fail_at = self.observer.feedback.last_stmt_index();
        let mut assert_failure = false;
        let mut p = program.clone();
        p.ops = program.ops.clone();

        // change failure stmt to the call stmt
        if let Some(FuzzStmt::Assert(assert)) = p.stmts.get(fail_at).map(|is| &is.stmt) {
            log!(trace, "assert failure");
            assert_failure = true;
            if let Some(stmt) = assert.get_stmt() {
                fail_at = stmt.get();
            }
        }

        log!(trace, "fail at: {}, status: {:?}", fail_at, status);
        if let Some(call) = p.get_call_stmt_mut(fail_at) {
            call.failure = true;
        } else {
            // Sometimes `fail_at` == stmts.len(),
            // may be double free in rust-side
            log!(debug, "fail at runtime!");
            return Ok(false);
        }

        // used for deduplication. It only track the crash function
        let mut p_debup = p.clone();
        p_debup.set_calls_track_cov(false);
        p_debup.get_call_stmt_mut(fail_at).unwrap().track_cov = true;
        // crate::log!(info, "before set failure: {}", program.serialize()?);
        // re-run it, and only track the crash location
        let re_status = self.executor.execute_program(&p_debup)?;
        if re_status.is_normal() {
            // it seems to be not stable
            return Ok(false);
        }
        let new_edges = self.observer.get_new_uniq_path(status);
        if new_edges.is_empty() {
            return Ok(false);
        }
        self.observer.merge_coverage(&new_edges, status);

        let id = self.depot.fetch_id(status);
        p.id = id;

        // Here we sanitize the program to mark the possible false positive results.
        // We infer the constraint for crash or timeout
        let new_constraints = if assert_failure {
            vec![]
        } else if status.is_crash() {
            self.crash_infer(&p)
                .with_context(|| format!("crash update constraint failed: {p}"))?
        } else if status.is_timeout() {
            self.timeout_infer(&p)
                .with_context(|| format!("timeout update constraint failed: {p}"))?
        } else {
            vec![]
        };
        if save {
            self.executor.sanitize_program(&p)?;
            let mut sanitize_result = SanitizeResult::conclusion(&p)?;
            sanitize_result.add_violated_constraints(&new_constraints)?;

            self.depot.save(status, &p, sync)?;
            self.depot
                .add_appendix(status, id, &sanitize_result.to_string())?;
        }
        Ok(true)
    }

    /// is the loop should continue or not?
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Print logs in terminal
    fn print_log(&self, in_round: bool) {
        if in_round && self.rounds % 50 != 0 {
            return;
        }
        let dur = self.start_at.elapsed();
        let speed = utils::calculate_speed(self.count, dur);
        let all_secs = dur.as_secs();
        let execute_log = format!(
            "#round: {}, #exec: {} ({}), #speed: {:.2} ({})",
            utils::format_count(self.rounds),
            utils::format_count(self.count),
            self.executor.usage.percent(all_secs),
            speed,
            self.executor.usage.avg_ms(),
        );
        log!(
            info,
            "{} {}, {}, {}",
            utils::format_time(all_secs),
            self.depot,
            self.observer.branches_state,
            execute_log
        );

        #[cfg(feature = "verbose")]
        {
            log::info!(target: "{Status}", "{} {} {} {} {} {} {} {} {} {}",
                dur.as_secs(),
                self.depot.inputs.size(),
                self.depot.crashes.size(),
                self.depot.hangs.size(),
                self.observer.branches_state.get_num_edge(),
                self.observer.branches_state.get_coverage_density(),
                self.rounds,
                self.count,
                speed,
                self.executor.usage.avg_ms().trim_end_matches("ms"),
            );
            log::info!(target: "{StatusOneShot}", "{} {} {} {} {} {} {} {} {} {}",
                dur.as_secs(),
                self.depot.inputs.size(),
                self.depot.crashes.size(),
                self.depot.hangs.size(),
                self.observer.branches_state.get_num_edge(),
                self.observer.branches_state.get_coverage_density(),
                self.rounds,
                self.count,
                speed,
                self.executor.usage.avg_ms().trim_end_matches("ms"),
            );
        }
    }
}

/// Get a running state
fn new_running_state() -> Arc<AtomicBool> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        log!(warn, "Ending Fuzzing.");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting SIGINT handler!");
    running
}

fn save_pid() -> eyre::Result<()> {
    let path = config::output_file_path("misc/pid");
    let mut f = std::fs::File::create(path)?;
    let pid = std::process::id();
    f.write_all(pid.to_string().as_bytes())?;
    crate::log!(info, "current pid: {}", pid);
    Ok(())
}

impl Drop for Fuzzer {
    fn drop(&mut self) {
        if self.rounds == 0 {
            return;
        }
        global_gadgets::get_instance()
            .save_gadgets_to_file()
            .unwrap();
        constraints::save_constraints_to_file().unwrap();
        effective::save_effective_args().unwrap();
    }
}
