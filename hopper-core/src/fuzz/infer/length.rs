//! Infer length related constraints (including Set and Range).
//!
//! APIs that use a number in the arguments to designate the boundary or index of an array pointer may suffer from
//! overflow errors if the number is incorrect.
//!
//! If the crash is caused by accessing a canary appended right after an array ($si\_addr$ is in the range of canary),
//! we try to figure out whether there is a length or index of a variable-sized array in the arguments.
//! Firstly, we locate which array has been overflowed. We denote the array's length as $N$. For each numerical value
//! in the call's arguments, we attempt to set it as $N-1$, $N$, and $N+1$, respectively.
//! If both $N$ and $N+1$ lead to a crash by accessing the canary, we add a RANGE constraint to set the value within
//! a range of $[0, N)$.
//! If only $N+1$ makes a crash, an EQUAL constraint is added to set the value to be the same as the array's length.

use std::cmp::Ordering;

use crate::{fuzz::*, fuzzer::*, log, log_trace, runtime::*, utils, CrashSig};

impl Fuzzer {
    /// Try to infer each number in pilot phase
    pub fn pilot_infer_number_length_and_resource(
        &mut self,
        program: &FuzzProgram,
        stmt_index: &StmtIndex,
        load_state: &ObjectState,
        call_stmt: &CallStmt,
        arg_pos: usize,
        prefix: &LocFields,
    ) -> eyre::Result<()> {
        // numbers include values whose types are: u16/i16/u32/i32/u64/i64
        let num_fields =
            load_state.find_fields_with(|s| utils::is_index_or_length_number(s.ty), false);
        log!(
            trace,
            "start infer numbers for stmt {:?} at function `{}`, #num_fields: {}",
            stmt_index.get(),
            call_stmt.fg.f_name,
            num_fields.len()
        );
        for f in num_fields {
            // Infer pointer related constraints, e.g index of array, or length of array
            if self
                .infer_number_length(program, call_stmt, stmt_index, arg_pos, prefix, &f)?
                .is_some()
            {
                continue;
            }

            // Infer resource/loop-related to avoid huge numbers
            let _ = self
                .infer_resource_exhaustion(program, call_stmt, stmt_index, arg_pos, prefix, &f)?;
        }
        Ok(())
    }

    // Make huge number to be smaller to avoid overflowing to other canary
    pub fn adjust_numbers_for_inference(
        &mut self,
        program: &mut FuzzProgram,
        fail_at: usize,
        crash_sig: &mut CrashSig,
    ) -> eyre::Result<()> {
        for stmt_i in 0..program.stmts.len() {
            if stmt_i == fail_at {
                break;
            }
            let FuzzStmt::Load(load) = &program.stmts[stmt_i].stmt else {
                continue;
            };
            let num_fields = load
                .state
                .find_fields_with(|s| utils::is_index_or_length_number(s.ty), false);
            for f in num_fields {
                let num_loc = Location::new(program.stmts[stmt_i].index.use_index(), f.clone());
                let val = program.find_number_by_loc(num_loc.clone())?;
                if val < 4096 {
                    continue;
                }
                let op = MutateOperator::new(num_loc, MutateOperation::IntSet { val: 4096.into() });
                let _status = self.execute_with_op(program, &op, false)?;
                if crash_sig.is_overflow_at_same_rip_or_canary() {
                    program.mutate_program_by_op(&op)?;
                    if let Some(new_crash_sig) = crate::get_crash_sig(Some(program)) {
                        *crash_sig = new_crash_sig;
                    }
                }
            }
        }
        Ok(())
    }

    /// Infer number length  constraints in an argument once overflow crash happens
    pub fn crash_infer_number_length(
        &mut self,
        program: &FuzzProgram,
        fail_at: usize,
        crash_sig: &CrashSig,
    ) -> eyre::Result<Option<ConstraintSig>> {
        let mut p: FuzzProgram = program.clone();
        let targets = find_infer_targets(self, &mut p, fail_at, crash_sig)?;
        for num_loc in targets {
            let stmt_index = num_loc.stmt_index.as_ref().unwrap();
            let stmt_i = stmt_index.get();
            let Some((call_i, call_stmt, arg_pos, prefix)) =
                p.find_stmt_loc_in_all_calls(stmt_i, fail_at)
            else {
                continue;
            };
            let f = &num_loc.fields;
            log_trace!("crash infer number length at load stmt: {stmt_i} for call {call_i}, location {arg_pos} - {f:?}");
            let found = self.infer_number_length(&p, call_stmt, stmt_index, arg_pos, &prefix, f)?;
            if found.is_some() {
                return Ok(found);
            }
        }
        log_trace!("fail to infer any number length");
        Ok(None)
    }

    /// Infer number's length related constraints, e.g index of array, or length of array
    pub fn infer_number_length(
        &mut self,
        program: &FuzzProgram,
        call_stmt: &CallStmt,
        stmt_index: &StmtIndex,
        arg_pos: usize,
        prefix: &LocFields,
        fields: &LocFields,
    ) -> eyre::Result<Option<ConstraintSig>> {
        let f_name = call_stmt.fg.f_name;
        let num_loc = Location::new(stmt_index.use_index(), fields.clone());
        let mut op: MutateOperator =
            MutateOperator::new(num_loc, MutateOperation::IntSet { val: 0.into() });

        for sample in get_sample_list(program) {
            // try to find a number that will overflow something
            log!(trace, "try sample: {sample}");
            op.op = MutateOperation::IntSet { val: sample.into() };
            let _status = self.execute_with_op(program, &op, false)?;
            let Some(crash_sig) = crate::get_crash_sig(Some(program)) else {
                continue;
            };
            log_trace!("program crash at sample: {sample}, segv_addr: {crash_sig:?}");

            // if crash in accessing canary,
            // try to find the corresponding pointer that the canary belongs to.
            let Some(canary_info) = crash_sig.get_canary_info() else {
                break;
            };

            let mut len = canary_info.len;
            let mut is_len = true;
            let mut p = program.clone();
            // try to find the length entry for the call
            let Some((len_entry_arg_pos, mut len_entry_fields)) =
                p.find_stmt_loc_for_call(canary_info.stmt_index, &call_stmt.args)
            else {
                log_trace!("can't find length entry, the canary is not in call's arguments");
                break;
            };
            // remove _pointer_ suffix, since length(xx) assume xx is a pointer instead of vector
            len_entry_fields.strip_pointer_suffix();
            log_trace!("len_entry: {len_entry_arg_pos} - {len_entry_fields:?}");
            // avoid the array is too small.
            if sample < len {
                continue;
            }
            if sample > len + 1 {
                // resize array's length to sample
                // there are cases the sample is not len or len + 1.
                // the program checks the length before use it, e.g if (K > 10) arr[K]
                // so K can't be too samll, or K can be large than LEN + 1
                let resize_p = resize_array_length(&p, canary_info.stmt_index, len, sample)?;
                op.op = MutateOperation::IntSet {
                    val: (sample + 1).into(),
                };
                let _ = self.execute_with_op(&resize_p, &op, false)?;
                if crash_sig.is_overflow_at_same_rip_or_canary() {
                    log!(trace, "resize array length to: {}", sample);
                    len = sample;
                    p = resize_p;
                }
            }

            // 1. run with boundary that must not overflow
            op.op = MutateOperation::IntSet {
                val: (len - 1).into(),
            };
            let status1 = self.execute_with_op(&p, &op, false)?;
            log!(trace, "N-1 status: {status1:?}");
            let mut coef = 1;
            if crash_sig.is_overflow_at_same_rip_or_canary() {
                // since we have checked the current val is 0 and 1 (it success),
                // the number X may determine the path that reach the crash, e.g if X > N { a[Y] },
                // where N >= 1
                // or X is one of the factor of a length. e.g len = X * Y or len = c * X (c is a constant).
                log!(trace, "crash at N-1, try to infer COEF");
                if let Some((new_p, infered_coef, new_len)) =
                    infer_coef(self, &p, &mut op, &crash_sig, canary_info, len)?
                {
                    p = new_p;
                    coef = infered_coef;
                    len = new_len;
                } else {
                    log_trace!("skip this round!");
                    break;
                }
            }

            // 2. run with boundary index that may overflow (used as index)
            // let bound = num::Integer::div_ceil(&len, &coef);
            let bound = len / coef;
            op.op = MutateOperation::IntSet { val: bound.into() };
            let status2 = self.execute_with_op(&p, &op, false)?;
            log!(trace, "N status: {status2:?}");
            if crash_sig.is_overflow_at_same_rip_or_canary() {
                log!(trace, "it is used as index instead of length");
                is_len = false;
            }

            // 3. run with boundary index that must overflow (used as length)
            op.op = MutateOperation::IntSet {
                val: (bound + 1).into(),
            };
            let status3 = self.execute_with_op(&p, &op, false)?;
            log!(trace, "N+1 status: {status3:?}");
            if !crash_sig.is_overflow_at_same_rip_or_canary() {
                // may appear in some special case, e.g. adding length checking before use it.
                // e.g. 1 page size for decode data_sz in libaom
                // otherwise, increase the length.
                if !veirfy_overflow_with_offsets(
                    self,
                    &p,
                    &mut op,
                    &crash_sig,
                    canary_info,
                    bound,
                    len,
                    coef,
                    &mut is_len,
                )? {
                    crate::log!(trace, "can't not find any crash");
                    // if it is not strictly related to the array, try next sample.
                    if coef > 1 {
                        crate::log!(trace, "continue sample");
                        continue;
                    }
                    break;
                }
            }

            // add length factor as constraint
            if coef > 1 {
                let c = Constraint::LengthFactor { coef: coef as u64 };
                let _factor_constraint = add_function_constraint(
                    f_name,
                    len_entry_arg_pos,
                    len_entry_fields.clone(),
                    c,
                    &format!("infer number at {}", p.id),
                )?;
            }

            let full_f = prefix.with_suffix(fields.clone());
            let len_entry = IrEntry::Length {
                arg_pos: Some(len_entry_arg_pos),
                fields: len_entry_fields.clone(),
                is_factor: coef > 1,
            };
            let c = if is_len {
                // if the number is both the length of arrary A and B,
                // then A and B must have the same length.
                if let Some(sig) = add_constraint_to_array(
                    &p,
                    f_name,
                    arg_pos,
                    &full_f,
                    len_entry_arg_pos,
                    &len_entry_fields,
                )? {
                    return Ok(Some(sig));
                }
                Constraint::should_be(len_entry)
            } else {
                Constraint::less_than(len_entry)
            };
            let new_constraint = add_function_constraint(
                f_name,
                arg_pos,
                full_f,
                c.clone(),
                &format!("infer number length at {}", p.id),
            )?;
            infer_factors(self, &p, &crash_sig, f_name, &c)?;
            return Ok(new_constraint);
        }
        Ok(None)
    }
}

/// Get existing length's location
fn find_existing_length_constraint_locations(
    program: &FuzzProgram,
    fail_at: usize,
    crash_sig: &CrashSig,
) -> eyre::Result<Vec<Location>> {
    let Some(canary_info) = crash_sig.get_canary_info() else {
        return Ok(vec![]);
    };
    let Some((_call_i, call_stmt, arr_arg_pos, mut arr_fields)) =
        program.find_stmt_loc_in_all_calls(canary_info.stmt_index, fail_at)
    else {
        return Ok(vec![]);
    };

    let f_name = call_stmt.fg.f_name;
    log!(trace, "try to find existing length constraint in {f_name}");
    arr_fields.strip_pointer_suffix();
    log!(trace, "array loc: {arr_arg_pos} - {arr_fields:?}");
    // if there are some length or range constraints on the array
    crate::inspect_function_constraint_with(f_name, |fc| {
        let mut locs = vec![];
        for (arg_i, cs) in fc.arg_constraints.iter().enumerate() {
            for c in cs.list.iter() {
                let Some((arg_pos, fields)) = c.constraint.get_length_loc() else {
                    continue;
                };
                // If exsting length constraints can not satisfy the usage of the array,
                // there are some other missing constraints, we try to set c.key to 1.
                if arg_pos == arr_arg_pos && fields == &arr_fields {
                    let arg_stmt = &call_stmt.args[arg_i];
                    if let Some(num_loc) =
                        c.key
                            .to_loc_for_refining(program, arg_stmt, &LocFields::default())
                    {
                        log!(trace, "existing length constraint at: {num_loc:?}");
                        locs.push(num_loc);
                    }
                }
            }
        }
        Ok(locs)
    })
}

/// Find targets for infering length or index
fn find_infer_targets(
    fuzzer: &mut Fuzzer,
    program: &mut FuzzProgram,
    fail_at: usize,
    crash_sig: &CrashSig,
) -> eyre::Result<Vec<Location>> {
    let existings = find_existing_length_constraint_locations(program, fail_at, crash_sig)?;
    // Make exsting length constraints to be 1 to avoid overflow
    // ATTN: but it can be normal after our refining
    for num_loc in &existings {
        let op = MutateOperator::new(num_loc.clone(), MutateOperation::IntSet { val: 1.into() });
        program.mutate_program_by_op(&op)?;
    }
    let mut targets = vec![];
    for stmt_i in 0..program.stmts.len() {
        if stmt_i == fail_at {
            break;
        }
        let FuzzStmt::Load(load) = &program.stmts[stmt_i].stmt else {
            continue;
        };
        let num_fields: Vec<LocFields> = load
            .state
            .find_fields_with(|s| utils::is_index_or_length_number(s.ty), false);
        if num_fields.is_empty() {
            log!(trace, "{stmt_i} has not numbers");
        }
        for f in num_fields {
            log!(trace, "try check number at [{stmt_i}] - {f}");
            // if the number fails at the same place when it is zero, then it is not length or index,
            // special case: SIGFPE
            let stmt_index = program.stmts[stmt_i].index.use_index();
            let num_loc = Location::new(stmt_index, f.clone());
            // skip those existings, and put them at the end of target list.
            if existings.contains(&num_loc) {
                continue;
            }
            let mut op =
                MutateOperator::new(num_loc.clone(), MutateOperation::IntSet { val: 0.into() });
            let _status = fuzzer.execute_with_op(program, &op, false)?;
            if crash_sig.is_overflow_at_same_rip_or_canary() {
                // log!(trace, "add assumption for length inference: {op:?}");
                continue;
            }
            log!(trace, "add loc into targets");
            targets.push(num_loc.clone());

            // magnify the number values.
            op.op = MutateOperation::IntSet { val: 1.into() };
            let _status = fuzzer.execute_with_op(program, &op, false)?;
            // if the number fails at the same place when it is one,
            // indicates there are some other constraints producing the clash.
            if crash_sig.is_overflow_at_same_rip_or_canary() {
                log!(trace, "set number to be 1 for length inference: {op:?}");
                // we assume the value is 1 in this round of inference
                program.mutate_program_by_op(&op)?;
                continue;
            }
            // if it is a combined length, and now it is too small,
            // if the number fails at the same place when it is a big value .
            // we set it a big value (> length).
            let mut len = 512;
            if let Some(canary_info) = crash_sig.get_canary_info() {
                if canary_info.len > 512 - 64 {
                    len = canary_info.len + 64;
                }
            }
            let val = program.find_number_by_loc(num_loc.clone())?;
            if val < len as u64 {
                op.op = MutateOperation::IntSet { val: len.into() };
                let _status = fuzzer.execute_with_op(program, &op, false)?;
                if crash_sig.is_overflow_at_same_rip_or_canary() {
                    log!(
                        trace,
                        "set number to be >len for length inference: {}",
                        op.serialize().unwrap()
                    );
                    program.mutate_program_by_op(&op)?;
                }
            }
        }
    }
    // append existing
    targets.extend(existings);

    Ok(targets)
}

/// Get a list of numbers for sampling overflow
fn get_sample_list(program: &FuzzProgram) -> Vec<usize> {
    let mut samples = vec![17, 33, 65, 129, 513, 4096];
    for is in &program.stmts {
        if let FuzzStmt::Load(load) = &is.stmt {
            let len = load.value.get_length();
            if len <= 1 {
                continue;
            }
            samples.push(len + 1);
            samples.push(len + 32);
        }
    }
    samples.sort();
    samples.dedup();
    samples
}

/// Infer coef of the length/index
fn infer_coef(
    fuzzer: &mut Fuzzer,
    program: &FuzzProgram,
    op: &mut MutateOperator,
    crash_sig: &CrashSig,
    canary_info: &CanaryInfo,
    len: usize,
) -> eyre::Result<Option<(FuzzProgram, usize, usize)>> {
    // let mut last_bound = 0;
    for k in 2..=16 {
        let assumed_bound = len / k;
        log!(trace, "k: {k}, assumed_bound: {assumed_bound}");
        if assumed_bound < 2 {// assumed_bound == last_bound
            log_trace!("bound is too samll, skip");
            break;
        }
        // last_bound = assumed_bound;
        op.op = MutateOperation::IntSet {
            val: (assumed_bound - 1).into(),
        };
        let _status = fuzzer.execute_with_op(program, op, false)?;
        // N-1 should not overflow!
        if crash_sig.is_overflow_at_same_rip_or_canary() {
            continue;
        }
        // `k` does not overflow now
        let assumed_coef = k;
        log!(trace, "assumed_coef: {assumed_coef}");
        // verify the coef
        // first we make the array's length to be multiple of coef, and check it
        let rem = len % assumed_coef;
        let (p, len) = if rem > 0 {
            let resize_p = resize_array_length(program, canary_info.stmt_index, len, len - rem)?;
            log_trace!("resize program to be multile of coef: {assumed_coef}, rem: {rem}");
            let _status = fuzzer.execute_with_op(&resize_p, op, false)?;
            if crash_sig.is_overflow_at_same_rip_or_canary() {
                log_trace!("the COEF for length is wrong.");
                continue;
            }
            (resize_p, len - rem)
        } else {
            (program.clone(), len)
        };
        let mut verified = true;
        for i in 2..5 {
            // make the array's length to be `len * i`, and check `i * assumed_len -1 `
            let resize_p = resize_array_length(&p, canary_info.stmt_index, len, i * len)?;
            log!(trace, "assume resize length to {}", len * i);
            op.op = MutateOperation::IntSet {
                val: (i * assumed_bound - 1).into(),
            };
            let _status = fuzzer.execute_with_op(&resize_p, op, false)?;
            if crash_sig.is_overflow_at_same_rip_or_canary() {
                log!(trace, "assumed_len fail, the COEF for length is wrong.");
                verified = false;
                break;
            }
        }
        if verified && assumed_coef > 1 {
            return Ok(Some((p, assumed_coef, len)));
        }
    }
    Ok(None)
}

fn veirfy_overflow_with_offsets(
    fuzzer: &mut Fuzzer,
    program: &FuzzProgram,
    op: &mut MutateOperator,
    crash_sig: &CrashSig,
    canary_info: &CanaryInfo,
    bound: usize,
    len: usize,
    coef: usize,
    is_len: &mut bool,
) -> eyre::Result<bool> {
    for offset in [4, 16, 64, 256, 4096] {
        log!(trace, "try to add offset: {offset}");
        let new_offset = bound + offset;
        op.op = MutateOperation::IntSet {
            val: new_offset.into(),
        };
        let _ = fuzzer.execute_with_op(program, op, false)?;
        if crash_sig.is_overflow_at_same_rip_or_canary() {
            // doule checking
            // we try to set buffer to be (len + offset)
            // so if the number is used for length, it won't crash,
            // if it is index, it will crash again.
            log_trace!("overflow at {new_offset} ({offset}), checking..");
            let addend = offset * coef;
            let resize_len = len + addend;
            log_trace!("resize buffer to {resize_len} by adding {addend} elements");
            let resize_p = resize_array_length(program, canary_info.stmt_index, len, resize_len)?;
            let _ = fuzzer.execute_with_op(&resize_p, op, false)?;
            // if is still crash
            // the number may be used as index
            if crash_sig.is_overflow_at_same_rip_or_canary() {
                log!(trace, "the program crash, the number has range contraint");
                // check if it is index or not again
                op.op = MutateOperation::IntSet {
                    val: (new_offset - 1).into(),
                };
                // it should not crash
                let _ = fuzzer.execute_with_op(&resize_p, op, false)?;
                if crash_sig.is_overflow_at_same_rip_or_canary() {
                    log!(trace, "it should not overflow!");
                    break;
                }
                *is_len = false;
            }
            // check the number again to ensure it is related to the array.
            // if number is set as len + next_offset(= 2 * offset),
            // but it is not overflow the array, they must be irrelevant.
            let next_offset = 2 * offset;
            op.op = MutateOperation::IntSet {
                val: (bound + next_offset).into(),
            };
            let _ = fuzzer.execute_with_op(&resize_p, op, false)?;
            // since some specifc checking for length, we assume it is ok if coef is 1.
            if coef > 1 && !crash_sig.is_overflow_at_same_rip_or_canary() {
                log!(trace, "it should overflow!");
                break;
            }
            return Ok(true);
        }
    }
    Ok(false)
}

/// Check and add constraint to array if two arrays should have the same length
fn add_constraint_to_array(
    program: &FuzzProgram,
    f_name: &str,
    arg_pos: usize,
    full_f: &LocFields,
    len_entry_arg_pos: usize,
    len_entry_fields: &LocFields,
) -> eyre::Result<Option<ConstraintSig>> {
    let Some((target_arg_pos, target_fields, existing_len_entry)) =
        inspect_function_constraint_mut_with(f_name, |fc| {
            for tc in fc.arg_constraints[arg_pos].list.iter_mut() {
                if &tc.key != full_f {
                    continue;
                }
                if let Constraint::SetVal {
                    val:
                        IrEntry::Length {
                            arg_pos: Some(existing_arg_pos),
                            fields: existing_fields,
                            is_factor: _,
                        },
                } = &mut tc.constraint
                {
                    if *existing_arg_pos != len_entry_arg_pos || existing_fields != len_entry_fields
                    {
                        let mut target_arg_pos = len_entry_arg_pos;
                        let mut target_fields = len_entry_fields.clone();
                        // make the order always the same
                        if *existing_arg_pos > target_arg_pos {
                            std::mem::swap(existing_arg_pos, &mut target_arg_pos);
                            std::mem::swap(existing_fields, &mut target_fields);
                        }
                        return Ok(Some((
                            target_arg_pos,
                            target_fields,
                            IrEntry::Length {
                                arg_pos: Some(*existing_arg_pos),
                                fields: existing_fields.clone(),
                                is_factor: false,
                            },
                        )));
                    }
                }
            }
            Ok(None)
        })?
    else {
        return Ok(None);
    };
    add_function_constraint(
        f_name,
        target_arg_pos,
        target_fields,
        Constraint::ArrayLength {
            len: existing_len_entry,
        },
        &format!("infer arrary length at {}", program.id),
    )
}

/// Resize program's `stmt_index` array fron `len` to `new_len`.
fn resize_array_length(
    program: &FuzzProgram,
    stmt_index: usize,
    len: usize,
    new_len: usize,
) -> eyre::Result<FuzzProgram> {
    log_trace!("try resize array length {stmt_index} from {len} to {new_len}");
    let mut resize_p: FuzzProgram = program.clone();
    let op = match new_len.cmp(&len) {
        Ordering::Greater => MutateOperation::VecPad {
            len: new_len,
            zero: true,
            rng_state: super::rng::gen_rng_state(),
        },
        Ordering::Less => MutateOperation::VecDel {
            offset: new_len - 1,
            len: len - new_len,
        },
        Ordering::Equal => return Ok(resize_p),
    };
    let len_loc = Location::stmt(resize_p.stmts[stmt_index].index.use_index());
    let op = MutateOperator::new(len_loc, op);
    resize_p.mutate_program_by_op(&op)?;
    log_trace!("resized: {resize_p}");
    Ok(resize_p)
}

/// Infer factors if find a new constraint
fn infer_factors(
    fuzzer: &mut Fuzzer,
    program: &FuzzProgram,
    crash_sig: &CrashSig,
    f_name: &str,
    constraint: &Constraint,
) -> eyre::Result<()> {
    let mut refined_p = program.clone();
    refined_p.refine_program()?;
    let _status = fuzzer.executor.execute_program(&refined_p)?;
    if !crash_sig.is_overflow_at_same_rip_or_canary() {
        log!(trace, "Do not crash at {crash_sig:?}");
        log!(trace, "program: {}", refined_p.serialize_all().unwrap());
        return Ok(());
    }
    // if has multiple length constraints, check if they are factors of a length
    let Some((arr_arg_pos, arr_fields)) = constraint.get_length_loc() else {
        return Ok(());
    };
    log!(trace, "try to infer factors..");
    let _ = crate::inspect_function_constraint_mut_with(f_name, |fc| {
        let mut factors = vec![];
        for (key_arg_pos, cs) in fc.arg_constraints.iter_mut().enumerate() {
            // crate::log_trace!("dst: {arr_arg_pos} - {arr_fields}");
            for c in &mut cs.list {
                let val = match &mut c.constraint {
                    Constraint::SetVal { val } => val,
                    Constraint::Range { min: _, max } => max,
                    _ => continue,
                };
                crate::log_trace!("len val: {val:?}");
                if let IrEntry::Length {
                    arg_pos,
                    fields,
                    is_factor,
                } = val
                {
                    if arg_pos == &Some(arr_arg_pos) && fields == arr_fields {
                        factors.push((key_arg_pos, &c.key, is_factor));
                    }
                }
            }
        }
        log!(trace, "found factors: {factors:?}");
        if factors.len() > 1 {
            for (key_arg_pos, key_fields, is_factor) in factors {
                if !*is_factor {
                    *is_factor = true;
                    let comment = format!(
                        "update {f_name}'s  <{key_arg_pos}> {key_fields} to be a factor of <{arr_arg_pos}> {arr_fields}",
                    );
                    crate::log!(trace, "{comment}");
                    crate::log_new_constraint(&comment);
                }
            }
        }
        Ok(())
    });
    Ok(())
}
