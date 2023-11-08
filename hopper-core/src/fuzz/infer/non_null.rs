//! Infer non-null constraint.
//!
//! APIs that do not check for null pointers can crash when invoked with null pointers.
//! It's often unclear whether this is a real bug, as some developers argue it is the user's responsibility
//! to perform null checks.
//!
//! If the call triggers a segmentation fault due to accessing a null pointer ($si\_addr$ is $0$ or close to $0$,
//! where $si\_addr$ is the address of the faulting memory reference), we locate each null pointer in the arguments,
//! sets it to the address of a protected memory chunk, and runs this mutated program again.
//! If the program crashes again at the same program location (indicated by the RIP register) and triggers illegal
//! access inside the protected memory chunk, it means the pointer is accessed without a null check in the API invocation.
//! In that case, we add a NON-NULL constraint for this pointer.

use eyre::ContextCompat;

use crate::{fuzz::*, fuzzer::*, log, runtime::*, utils, CrashSig};

impl Fuzzer {
    /// Try to remove init function for an opaque pointer, and check if they are necessary.
    pub fn pilot_infer_need_init(
        &mut self,
        program: &FuzzProgram,
        stmt_index: &StmtIndex,
        load_state: &ObjectState,
        call_stmt: &CallStmt,
        arg_pos: usize,
        prefix: &LocFields,
    ) -> eyre::Result<()> {
        if utils::is_opaque_pointer(load_state.ty) && program.has_been_inited(stmt_index).is_some()
        {
            let op = MutateOperator::new(
                Location::stmt(stmt_index.use_index()),
                MutateOperation::RemoveInitOpaque,
            );
            let status = self.execute_with_op(program, &op, false)?;
            if !status.is_normal() {
                let mut full_f = prefix.clone();
                full_f.strip_pointer_suffix();
                add_function_constraint(
                    call_stmt.fg.f_name,
                    arg_pos,
                    full_f,
                    Constraint::NeedInit,
                    "add need init for opaque in pilot-infer",
                )?;
            }
        }
        Ok(())
    }

    /// Try to set each pointer to be NULL, if it crash, the pointer should not be NULL.
    pub fn pilot_infer_non_null(
        &mut self,
        program: &FuzzProgram,
        stmt_index: &StmtIndex,
        load_state: &ObjectState,
        call_stmt: &CallStmt,
        arg_pos: usize,
        prefix: &LocFields,
    ) -> eyre::Result<()> {
        let non_null_fields = load_state.find_fields_with(|s| s.is_non_null(), false);
        let f_name = call_stmt.fg.f_name;
        log!(
            trace,
            "start infer pointer for stmt {} at function `{f_name}`: {non_null_fields:?}",
            stmt_index.get()
        );
        for f in non_null_fields {
            log!(trace, "try to set field {:?} as null", f);
            // we try to set the pointer to be null
            let op = MutateOperator::new(
                Location::new(stmt_index.use_index(), f.clone()),
                MutateOperation::PointerNull,
            );
            let status = self.execute_with_op(program, &op, false)?;
            let field_state = load_state.get_child_by_fields(f.as_slice())?;
            // Do not impose the non-null constraint if the field is a pointer that points to an object
            // that has the same type as the field's parent.
            // This will probably incur an endless loop when refining.
            if !f.is_empty() {
                let struct_type_name = field_state.get_parent().context("has parent")?.ty;
                let is_nested = utils::is_pointer_type(field_state.ty)
                    && utils::get_pointer_inner(field_state.ty).unwrap() == struct_type_name;
                if is_nested {
                    continue;
                }
            }
            if !status.is_normal() {
                // should not be opaque
                let full_f = prefix.with_suffix(f);
                let c = if utils::is_opaque_pointer(field_state.ty) {
                    Constraint::NeedInit
                } else {
                    Constraint::NonNull
                };
                add_function_constraint(f_name, arg_pos, full_f, c, "set null in pilot-infer")?;
            }
        }
        Ok(())
    }

    /// Infer null constraints in an argument once overflow crash happens
    pub fn crash_infer_null_for_overflow(
        &mut self,
        program: &FuzzProgram,
        call_i: usize,
        call_stmt: &CallStmt,
        stmt_index: &StmtIndex,
        load_state: &ObjectState,
        arg_pos: usize,
        prefix: LocFields,
        crash_sig: &CrashSig,
    ) -> eyre::Result<Option<ConstraintSig>> {
        crate::log!(
            trace,
            "crash infer non-null at load stmt: {} for call {call_i}",
            stmt_index.get()
        );
        // Infer pointer: set NULL pointer to NON-NULL
        let null_fields = load_state.find_fields_with(|s| s.is_null(), false);
        if null_fields.is_empty() {
            return Ok(None);
        }
        crate::log!(
            trace,
            "start inferring non-null and need-init constraint. load index: {}, null_fields: {:?}",
            stmt_index.get(),
            null_fields
        );
        for f in null_fields {
            let field_state = load_state.get_child_by_fields(f.as_slice())?;
            let is_opaque = utils::is_opaque_pointer(field_state.ty);
            let loc = Location::new(stmt_index.use_index(), f.clone());
            // We set the pointer to point to a address of a canary
            let op = MutateOperator::new(loc, MutateOperation::PointerCanary);
            let _status = self.execute_with_op(program, &op, false)?;
            let cur_rip = self.observer.feedback.instrs.rip_addr;
            let cur_segv = self.observer.feedback.instrs.segv_addr;
            crate::log!(trace, "field: {f:?}, segv: {cur_segv:X}, rip: {cur_rip:X}");
            // if the program crash at the same place by de-refercing the address in the canary!
            if crate::is_overflow_canary() {
                let cur_hash = self.observer.feedback.path.hash_trace();
                crate::log!(trace, "hash: {cur_hash}, rip: {cur_rip}");
                if crash_sig.is_null_function_pointer() {
                    // function pointer is directly called instead of de-referencing.
                    // if rip is 0, it is a null function poiner, we should compare hash.
                    if cur_hash != crash_sig.hash {
                        crate::log!(
                            trace,
                            "skip since hash ({}, {}) is not same",
                            cur_hash,
                            crash_sig.hash
                        );
                        continue;
                    }
                } else if cur_rip != crash_sig.rip {
                    crate::log!(
                        trace,
                        "skip since ({}, {}) rip is not same",
                        cur_rip,
                        crash_sig.rip
                    );
                    // Though RIP indicates the program is not crash at the same place,
                    // some API codes check the null pointer inconsistently,
                    // they may check null at A and then do not check it at B,
                    // so the crash rip changes.
                    // Thus, we try to set it to be non-null again
                    let loc = Location::new(stmt_index.use_index(), f.clone());
                    let op = if is_opaque {
                        MutateOperation::InitOpaque { call_i }
                    } else {
                        MutateOperation::PointerGen {
                            rng_state: rng::gen_rng_state(),
                        }
                    };
                    let op = MutateOperator::new(loc, op);
                    let status = self.execute_with_op(program, &op, true)?;
                    if flag::is_incomplete_gen() {
                        log!(trace, "incomplete mutation");
                        continue;
                    }
                    // if still access null
                    if status.is_overflow() && crate::is_access_null() {
                        crate::log!(trace, "still access null after refining");
                        continue;
                    }
                    // exit early
                    if self.observer.feedback.track_nothing() {
                        log!(trace, "exit before invoking");
                        continue;
                    }
                }
                let constraint = if is_opaque {
                    Constraint::NeedInit
                } else {
                    Constraint::NonNull
                };
                log!(trace, "prefix: {prefix:?} , f: {f:?}");
                let full_f = prefix.with_suffix(f);
                add_function_constraint(
                    call_stmt.fg.f_name,
                    arg_pos,
                    full_f.clone(),
                    constraint.clone(),
                    &format!("infer non-null in crash {}", program.id),
                )?;
                let constraint_sig = ConstraintSig {
                    f_name: call_stmt.fg.f_name.to_string(),
                    arg_pos,
                    fields: full_f,
                    constraint,
                };
                return Ok(Some(constraint_sig));
            }
        }
        Ok(None)
    }

    /// Infer constraints in an argument once abort happens
    pub fn crash_infer_null_for_abort(
        &mut self,
        program: &FuzzProgram,
        call_i: usize,
        call_stmt: &CallStmt,
        stmt_index: &StmtIndex,
        load_state: &ObjectState,
        arg_pos: usize,
        prefix: LocFields,
    ) -> eyre::Result<Option<ConstraintSig>> {
        crate::log!(trace, "infer null for abort!");
        let null_fields = load_state.find_fields_with(|s| s.is_null(), false);
        // the pointer-to-canary trick is not works for these cases,
        // since they will pass the assert and crash at other place.
        // so we try to filp the pointers to be NON-NULL.
        for f in null_fields {
            let field_state = load_state.get_child_by_fields(f.as_slice())?;
            let is_opaque = utils::is_opaque_pointer(field_state.ty);
            let loc = Location::new(stmt_index.use_index(), f.clone());
            let op = if is_opaque {
                MutateOperation::InitOpaque { call_i }
            } else {
                MutateOperation::PointerGen {
                    rng_state: rng::gen_rng_state(),
                }
            };
            let op = MutateOperator::new(loc.clone(), op);
            let status = self.execute_with_op(program, &op, true)?;
            if flag::is_incomplete_gen() {
                log!(trace, "incomplete mutation");
                continue;
            }
            if status.is_ignore() {
                log!(
                    warn,
                    "generate wrong program during infer abort for:\n  {}",
                    program.serialize_all()?
                );
                continue;
            }
            // assert to exit early.
            if self.observer.feedback.track_nothing() {
                log!(trace, "exit before invoking");
                continue;
            }

            if !status.is_abort() {
                let full_f = prefix.with_suffix(f);
                let constraint = if is_opaque {
                    Constraint::NeedInit
                } else {
                    Constraint::NonNull
                };
                add_function_constraint(
                    call_stmt.fg.f_name,
                    arg_pos,
                    full_f.clone(),
                    constraint.clone(),
                    "infer non-null in abort",
                )?;
                let constraint_sig = Some(ConstraintSig {
                    f_name: call_stmt.fg.f_name.to_string(),
                    arg_pos,
                    fields: full_f,
                    constraint,
                });
                return Ok(constraint_sig);
            }
        }
        Ok(None)
    }
}
