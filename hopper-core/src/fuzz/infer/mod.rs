//! Constraints inference learns functions and types' constraints
//! e.g. arguments should be non-null, some integers are loop-related ...
//! The constraints will be used in subsequent fuzzing.

mod array;
mod cast;
mod context;
mod file;
mod length;
mod non_null;
mod opaque;
mod res;
mod sigfpe;

use eyre::ContextCompat;

use crate::{config, execute::StatusType, fuzz::*, fuzzer::*, log, runtime::*, utils};

impl Fuzzer {
    /// Run inferences at pilot phase, it will try to sample some simplest inputs,
    /// and executes them to infer some relationship as constraints.
    pub fn pilot_infer(&mut self) -> eyre::Result<()> {
        log!(info, "start pilot infer...");
        let to_infer_funcs = get_ordered_func_list();
        let num_f = to_infer_funcs.len();
        let mut suc_num = 0;
        let mut retry_funcs = vec![];
        for (f_i, f_name) in to_infer_funcs.into_iter().enumerate() {
            if !self.is_running() {
                break;
            }
            // disable infer contraints, used for evalution
            if !config::ENABLE_REFINE {
                set_function_constraint_with(f_name, |fc| fc.can_succeed = true)?;
                continue;
            }
            log!(info, "[{f_i}/{num_f}] start pilot infer `{f_name}` ..");
            crate::set_pilot_infer(true);
            let (program, status) = self.generate_pilot_det_program(f_name)?;
            // If the `pilot-det` program succeeds,
            // we try to sample based on the input and then infer its constraints.
            let can_succeed = if status.is_normal() {
                self.infer_by_review_program(&program)?;
                self.pilot_infer_func_constraints(&program)?;
                self.verify_func_constraints(f_name)?
            } else {
                log!(warn, "fail to generate successful pilot-det program!");
                log!(warn, "pilot-det program: {}", program.serialize_all()?);
                false
            };
            set_function_constraint_with(f_name, |fc| fc.can_succeed = can_succeed)?;
            // log something
            if can_succeed {
                log!(info, "API `{f_name}` succeed after refining.");
                suc_num += 1;
                crate::set_pilot_infer(false);
                self.pilot_generate_func(f_name)?;
            } else {
                retry_funcs.push(f_name);
                log!(warn, "API `{f_name}` crashed after refining.");
            }
        }
        log!(
            info,
            "finish pilot infer, suc / all: {suc_num} / {num_f}..."
        );
        // retry those failure functions since their required functions may inferred after it in the `to_infer_funcs` list.
        let retry_num = retry_funcs.len();
        let mut retry_suc_num = 0;
        for (f_i, f_name) in retry_funcs.into_iter().enumerate() {
            if !self.is_running() {
                break;
            }
            log!(info, "[{f_i}/{retry_num}] retry to infer failed `{f_name}`");
            crate::set_pilot_infer(true);
            let (program, status) = self.generate_pilot_det_program(f_name)?;
            if status.is_normal() {
                self.infer_by_review_program(&program)?;
                self.pilot_infer_func_constraints(&program)?;
                let can_succeed = self.verify_func_constraints(f_name)?;
                if can_succeed {
                    log!(info, "API `{f_name}` succeed after retrying");
                    retry_suc_num += 1;
                    set_function_constraint_with(f_name, |fc| fc.can_succeed = can_succeed)?;
                    crate::set_pilot_infer(false);
                    self.pilot_generate_func(f_name)?;
                }
            }
        }
        if retry_num > 0 {
            log!(
                info,
                "finish pilot infer (retry), suc / all: {retry_suc_num} / {retry_num}..."
            );
        }
        save_constraints_to_file()?;
        crate::set_pilot_infer(false);
        Ok(())
    }

    /// We first generate `pilot-det` program,
    /// which has small numbers & non-null pointer in its arguments & fields.
    fn generate_pilot_det_program(
        &mut self,
        f_name: &str,
    ) -> eyre::Result<(FuzzProgram, StatusType)> {
        set_pilot_det(true);
        let mut program = FuzzProgram::generate_program_for_func(f_name)?;
        log!(debug, "pilot-det program\n{}", program.serialize()?);
        let mut status = self.executor.execute_program(&program)?;
        if !status.is_normal() {
            // try to make crash program to be success during pilot inference
            for is in &program.stmts {
                if let FuzzStmt::Load(load) = &is.stmt {
                    // try to set void pointer (may be there is a NON_NULL constraint)
                    if let Some(ps) = &load.state.pointer {
                        if ps.pointer_location.is_null() && utils::is_void_type(ps.pointer_type) {
                            log!(debug, "try to set void pointer");
                            let op = MutateOperator::new(
                                Location::stmt(is.index.use_index()),
                                MutateOperation::PointerGenChar,
                            );
                            let mut p = program.clone();
                            p.mutate_program_by_op(&op)?;
                            log!(debug, "crafted program : {}", p.serialize_all()?);
                            let new_status = self.executor.execute_program(&p)?;
                            log!(debug, "crafted status : {:?}", new_status);
                            if new_status.is_normal() {
                                status = new_status;
                                program = p;
                                break;
                            }
                        }
                    }
                }
            }
        }
        set_pilot_det(false);
        if !status.is_normal() {
            // try to infer some constraints for the crashes
            self.verify_func_constraints(f_name)?;
            set_pilot_det(true);
            program = FuzzProgram::generate_program_for_func(f_name)?;
            log!(
                debug,
                "re-generate pilot-det program\n{}",
                program.serialize()?
            );
            status = self.executor.execute_program(&program)?;
            set_pilot_det(false);
        }
        Ok((program, status))
    }

    /// Infer constraints by the feedback of reviewing program
    fn infer_by_review_program(&mut self, program: &FuzzProgram) -> eyre::Result<StatusType> {
        let mut p = program.clone();
        // avoid id collision in review
        p.id = 1000000;
        let review_status = self.executor.review_program(&p)?;
        let review = crate::feedback::ReviewResult::read_from_file(&mut p)?;
        review.add_into_constraints(&p)?;
        Ok(review_status)
    }

    /// Infer constraints for a function in pilot phase
    fn pilot_infer_func_constraints(&mut self, program: &FuzzProgram) -> eyre::Result<()> {
        // call is at the second to last one in program's statments
        let call_stmt = program.get_target_stmt().context("has target call")?;
        for is in &program.stmts {
            // infer each load statements
            if let FuzzStmt::Load(load) = &is.stmt {
                self.pilot_infer_load_stmt_constraints(program, &is.index, &load.state, call_stmt)?;
            }
        }
        Ok(())
    }

    /// Infer constraints in an argument in pilot phase
    fn pilot_infer_load_stmt_constraints(
        &mut self,
        program: &FuzzProgram,
        stmt_index: &StmtIndex,
        load_state: &ObjectState,
        call_stmt: &CallStmt,
    ) -> eyre::Result<()> {
        // find the relationship between the load statement and call statement
        let Some((arg_pos, prefix)) =
            program.find_stmt_loc_for_call(stmt_index.get(), &call_stmt.args)
        else {
            return Ok(());
        };
        // ----------------------------------------
        // 0. Infer void pointer: try to cast it to char*
        // ----------------------------------------
        // only infer void pointer arguments
        if prefix.is_empty() {
            self.pilot_infer_void_type(program, stmt_index, call_stmt, arg_pos)?;
        }
        // ----------------------------------------
        // 1. Infer pointer : set the pointer to NULL
        // ----------------------------------------
        // 1.1 remove init opaque
        self.pilot_infer_need_init(program, stmt_index, load_state, call_stmt, arg_pos, &prefix)?;
        // 1.2 set null pointer
        self.pilot_infer_non_null(program, stmt_index, load_state, call_stmt, arg_pos, &prefix)?;
        // ----------------------------------------------------
        // 2. Infer numbers
        // ----------------------------------------------------
        self.pilot_infer_number_length_and_resource(
            program, stmt_index, load_state, call_stmt, arg_pos, &prefix,
        )?;
        Ok(())
    }

    /// Verify if the function can be successful invoked with generated arguaments
    /// with constraints or not
    fn verify_func_constraints(&mut self, f_name: &str) -> eyre::Result<bool> {
        let mut fail_program = None;
        let mut fail_cnt = 0;
        log!(info, "start verify function `{}`", f_name);
        let mut i = 0;
        let mut crash_infered_cnt = 0;
        while i < config::ROUND_PILOT_NUM {
            i += 1;
            let program = FuzzProgram::generate_program_for_func(f_name)?;
            crate::log_trace!("pilot check #program-{i}\n{program}");
            if program.stmts.len() > config::MAX_STMTS_LEN || is_incomplete_gen() {
                continue;
            }
            let status = self.executor.execute_program(&program)?;
            if !status.is_normal() {
                let mut crash_program = program.clone();
                fail_program = Some(program);
                if crash_infered_cnt < 8 {
                    crash_infered_cnt += 1;
                    let fail_at = self.observer.feedback.last_stmt_index();
                    log!(trace, "crash fail at: {fail_at}");
                    if let Some(call) = crash_program.get_call_stmt_mut(fail_at) {
                        call.failure = true;
                        let mut infered = vec![];
                        if status.is_crash() {
                            infered = self.crash_infer(&crash_program)?
                        } else if status.is_timeout() {
                            infered = self.timeout_infer(&crash_program)?
                        }
                        if !infered.is_empty() {
                            log!(info, "crash infer new constraints, verify again");
                            fail_program = None;
                            i = 0;
                            continue;
                        }
                    } else {
                        log!(warn, "fail at error index: {fail_at}");
                        break;
                    }
                }
                fail_cnt += 1;
                if fail_cnt > 25 {
                    log!(trace, "fail too many times, break");
                    break;
                }
            }
        }
        log!(info, "finish verify function `{f_name}`");
        if let Some(p) = fail_program.as_ref() {
            log!(warn, "verify fail program: {}", p.serialize_all()?);
        }
        Ok(fail_program.is_none())
    }

    /// Infer constraints for new seeds
    pub fn seed_infer(&mut self, program: &FuzzProgram) -> eyre::Result<Vec<ConstraintSig>> {
        let mut new_constraints = vec![];
        crate::log!(trace, "infer new seed");
        if let Some(c) = self.infer_file_fd(program)? {
            new_constraints.push(c);
        }
        Ok(new_constraints)
    }

    /// Infer constraints once crash happens
    pub fn crash_infer(&mut self, program: &FuzzProgram) -> eyre::Result<Vec<ConstraintSig>> {
        let mut new_constraints = vec![];
        crate::log!(debug, "infer crash: {}", program.serialize_all()?);
        let mut p = program.clone();

        macro_rules! crash_iter {
            ( $p:ident, $max:ident, $list:ident, $f:ident, $($arg:expr),* ) => { {
                let mut has_new = false;
                for is in &$p.stmts {
                    if is.index.get() == $max {
                        break;
                    }
                    if let FuzzStmt::Load(load) = &is.stmt {
                        let stmt_index = &is.index;
                        // the argument leads to crash may be not in crash call
                        if let Some((call_i, call_stmt, arg_pos, prefix)) =
                            $p.find_stmt_loc_in_all_calls(stmt_index.get(), $max)
                        {
                            if let Some(new_one) = self.$f(
                                &p, call_i, call_stmt, stmt_index, &load.state, arg_pos, prefix, $($arg),*
                            )? {
                                $list.push(new_one);
                                has_new = true;
                            }
                        }
                    }
                }
                has_new
            } };
            ( $p:ident, $max:ident, $list:ident, $f:ident) => (crash_iter!($p, $max, $list, $f,))
        }

        // check crash for update opeartion
        if let Some(c) = self.infer_opaque_if_update_fail(program)? {
            new_constraints.push(c);
            return Ok(new_constraints);
        }

        for _ in 0..3 {
            // warp with a loop to continue infer in some cases
            let mut has_new = false;
            let status = self.infer_by_review_program(&p)?;
            let fail_at = p
                .get_fail_stmt_index()
                .with_context(|| format!("Can't find fail stmt, program: {p}"))?
                .get();
            // only track crash invoking
            p.set_calls_track_cov(false);
            p.get_call_stmt_mut(fail_at).unwrap().track_cov = true;

            // avoid assertion
            // we prefer make assert to exit instead of aborting that we need to infer them
            if config::ENABLE_INFER_ABORT && status.is_abort() {
                // assert null
                has_new |= crash_iter!(p, fail_at, new_constraints, crash_infer_null_for_abort);
                // TODO: other assertion.. e.g. compare
            }

            // check SIGFPE
            if status.is_sigfpe() {
                let _ = self.executor.execute_program(&p)?;
                let cmp_list = self.observer.feedback.instrs.get_cmp_ids();
                let last_cmps = if cmp_list.len() > 10 {
                    &cmp_list[cmp_list.len() - 10..]
                } else {
                    &cmp_list[..]
                };
                has_new |= crash_iter!(p, fail_at, new_constraints, infer_sigfpe, last_cmps);
            }

            // memory error: segv
            if status.is_overflow() {
                let _ = self.executor.execute_program(&p)?;
                if let Some(mut crash_sig) = crate::get_crash_sig(Some(&p)) {
                    crash_sig.hash = self.observer.feedback.path.hash_trace();
                    crate::log!(trace, "crash sig : {crash_sig:?}");
                    if crash_sig.is_null_access() {
                        has_new |= crash_iter!(
                            p,
                            fail_at,
                            new_constraints,
                            crash_infer_null_for_overflow,
                            &crash_sig
                        );
                      
                    } else {
                        // make huge number to be smaller to avoid overflowing to other canary
                        self.adjust_numbers_for_inference(&mut p, fail_at, &mut crash_sig)?;

                        // if crash_sig.is_overflow_canary()
                        if let Some(c) = self.crash_infer_number_length(&p, fail_at, &crash_sig)? {
                            new_constraints.push(c);
                            has_new = true;
                        }
                        // infer opaque type // partial opaque
                        if !has_new {
                            if let Some(c) = self.infer_opaque_type(&p, fail_at, &crash_sig)? {
                                new_constraints.push(c);
                                has_new = true;
                            }
                        }
                        // if cannot find any number constarints, try to padding buffers to find ARRAY-LEN constraints
                        if !has_new {
                            if let Some(c) = self.infer_array_length(&p, fail_at, &crash_sig)? {
                                new_constraints.push(c);
                                has_new = true;
                            }
                        }
                    }
                    if !has_new {
                        // OOM: malloc return NULL or access overflow
                        if let Some(c) = self.crash_infer_resource_exhaustion(&p, fail_at)? {
                            new_constraints.push(c);
                            has_new = true;
                        }
                    }
                    if !has_new {
                        // check void cast
                        has_new = self.infer_void_cast(&p, fail_at, &crash_sig)?;
                    }
                }
            }

            if has_new {
                // refine with new adding constraints
                p.refine_program()?;
                let status = self.executor.execute_program(&p)?;
                crate::log!(trace, "updated program: {p}");
                // if it still crash we run next loop
                if status.is_crash() {
                    crate::log!(trace, "still crash after length inference");
                    continue;
                }
            }

            break;
        }
        // check contexts
        if new_constraints.is_empty() {
            if let Some(c) = self.infer_broken_contexts(program)? {
                new_constraints.push(c);
            }
        }
        Ok(new_constraints)
    }

    /// Infer if program timeout
    pub fn timeout_infer(&mut self, program: &FuzzProgram) -> eyre::Result<Vec<ConstraintSig>> {
        let mut new_constraints = vec![];
        crate::log!(debug, "infer timeout: {}", program.serialize_all()?);
        let fail_at = program
            .get_fail_stmt_index()
            .with_context(|| {
                format! {"Can't find fail stmt, program: {}", program.serialize().unwrap()}
            })?
            .get();
        if let Some(c) = self.crash_infer_resource_exhaustion(program, fail_at)? {
            new_constraints.push(c);
        }
        Ok(new_constraints)
    }

    /// Mutate program with operation, and then execute it.
    pub fn execute_with_op(
        &mut self,
        program: &FuzzProgram,
        op: &MutateOperator,
        refine: bool,
    ) -> eyre::Result<StatusType> {
        let mut p = program.clone();
        log!(trace, "mutate with op : {}", op.serialize()?);
        flag::set_incomplete_gen(false);
        p.mutate_program_by_op(op)?;
        if refine {
            p.refine_program()?;
        }
        log!(trace, "mutated program : {}", p.serialize()?);
        let status = self.executor.execute_program(&p)?;
        Ok(status)
    }
}

/// Find all functions that we need to infer in a proper order
fn get_ordered_func_list() -> Vec<&'static str> {
    let mut to_infer_funcs: Vec<&'static str> = vec![];
    let gadgets = global_gadgets::get_instance();
    let mut fgs: Vec<(&FnGadget, bool)> = gadgets
        .functions
        .values()
        .filter(|fg| filter_function_constraint_with(fg.f_name, |fc| !fc.internal))
        .map(|fg| (fg, false))
        .collect();
    // crate::log!(trace, "fgs: {fgs:?}");
    // if a function can be generated with the functions in existing `to_infer` list,
    // then it can be merged into the list.
    for round in 0..20 {
        for (fg, pick) in &mut fgs {
            if *pick {
                continue;
            }
            let mut can_gen = true;
            let f_name = fg.f_name;
            crate::log!(trace, "try pick {f_name}");
            for (i, arg_type) in fg.arg_types.iter().enumerate() {
                let mut may_be_opaque = utils::is_opaque_type(arg_type);
                if let Some(inner) = utils::get_pointer_inner(arg_type) {
                    if !utils::is_primitive_type(inner) {
                        may_be_opaque = true;
                    }
                }
                if may_be_opaque {
                    if round == 0 {
                        crate::log!(trace, "arg-{i} is opaque pointer in round-0, skip");
                        can_gen = false;
                        break;
                    }
                    let mut has_provider = false;
                    let alias_type = fg.alias_arg_types[i];
                    if let Some(inner) = utils::get_pointer_inner(alias_type) {
                        let mut_ptr = utils::mut_pointer_type(inner);
                        if let Some(fs) = gadgets.ret_graph.get(mut_ptr.as_str()) {
                            if let Some(f) = fs.iter().find(|&f| to_infer_funcs.contains(f)) {
                                crate::log!(trace, "{f} return arg-{i}");
                                continue;
                            }
                            has_provider = true;
                        }
                        let const_ptr = utils::const_pointer_type(inner);
                        if let Some(fs) = gadgets.ret_graph.get(const_ptr.as_str()) {
                            if let Some(f) = fs.iter().find(|&f| to_infer_funcs.contains(f)) {
                                crate::log!(trace, "{f} return arg-{i}");
                                continue;
                            }
                            has_provider = true;
                        }
                    } else if let Some(fs) = gadgets.ret_graph.get(alias_type) {
                        if let Some(f) = fs.iter().find(|&f| to_infer_funcs.contains(f)) {
                            crate::log!(trace, "{f} return arg-{i}");
                            continue;
                        }
                        has_provider = true;
                    }
                    let ptr_type = utils::mut_pointer_type(alias_type);
                    if let Some(fs) = gadgets.arg_graph.get(ptr_type.as_str()) {
                        if let Some((f, _)) = fs.iter().find(|&(f, _)| to_infer_funcs.contains(f)) {
                            crate::log!(trace, "{f} init arg-{i}");
                            continue;
                        }
                        has_provider = true;
                    }
                    let ptr_type = utils::const_pointer_type(alias_type);
                    if let Some(fs) = gadgets.arg_graph.get(ptr_type.as_str()) {
                        if let Some((f, _)) = fs.iter().find(|&(f, _)| to_infer_funcs.contains(f)) {
                            crate::log!(trace, "{f} init arg-{i}");
                            continue;
                        }
                        has_provider = true;
                    }
                    // found nothing
                    if has_provider {
                        crate::log!(trace, "arg-{i} can't find any producer in list, skip");
                        can_gen = false;
                    }
                    break;
                }
            }
            if can_gen {
                to_infer_funcs.push(f_name);
                *pick = true;
            }
        }
    }
    // infer remain ones
    for (fg, pick) in &mut fgs {
        if !*pick && literal::is_init_function_by_name(fg.f_name) {
            to_infer_funcs.push(fg.f_name);
            *pick = true;
        }
    }
    for (fg, pick) in &mut fgs {
        if !*pick {
            to_infer_funcs.push(fg.f_name);
        }
    }

    to_infer_funcs
}
