//! Infer array's minimal length.
//!
//! Some APIs assume that the arrays referenced by the pointers have sufficient elements rather than asking for
//! arguments indicating boundaries.
//!
//! We attempt to pad the arrays in the arguments to a specific length K (e.g., 64) to see whether it resolves the crash.
//! If so, an ARRAY-LEN constraint is added to ensure that this array is at least K bytes.

use crate::{fuzz::*, fuzzer::*, runtime::*, CrashSig};

impl Fuzzer {
    /// Infer array's implicit length by padding
    pub fn infer_array_length(
        &mut self,
        program: &FuzzProgram,
        fail_at: usize,
        crash_sig: &CrashSig,
    ) -> eyre::Result<Option<ConstraintSig>> {
        let Some(canary_info) = crash_sig.get_canary_info() else {
            return Ok(None);
        };
        let Some((_call_i, call_stmt, arg_pos, fields)) =
            program.find_stmt_loc_in_all_calls(canary_info.stmt_index, fail_at)
        else {
            return Ok(None);
        };
        let stmt_index = &call_stmt.args[arg_pos];
        crate::log_trace!(
            "try to infer array length, array loc is arg_pos: {arg_pos} fields: {fields:?}"
        );
        let loc = fields.to_loc_for_refining(program, stmt_index, &LocFields::default());
        if loc.is_none() {
            crate::log!(trace, "can't find loc!");
            return Ok(None);
        }
        let loc = loc.unwrap();
        let mut paddings = vec![4, 64, 128, 256, 512, 1024, 4096];
        // if it is not an array of primitive types
        if let FuzzStmt::Load(load) = &program.stmts[canary_info.stmt_index].stmt {
            if let Some(ch) = load.state.children.first() {
                if !ch.children.is_empty() {
                    paddings = vec![4, 8, 16, 32];
                }
            }
        }
        for pad_size in paddings {
            if canary_info.len >= pad_size {
                continue;
            }
            let rng_state = rng::gen_rng_state();
            let pad_op = MutateOperator::new(
                loc.clone(),
                MutateOperation::VecPad {
                    len: pad_size,
                    zero: false,
                    rng_state,
                },
            );
            let _status = self.execute_with_op(program, &pad_op, false)?;
            if crash_sig.is_overflow_at_same_rip_or_canary() {
                continue;
            }
            // we should verify it!
            // check all numbers, try to set them to big values
            let mut refined_p = program.clone();
            refined_p.mutate_program_by_op(&pad_op)?;
            for is in &program.stmts {
                if is.index.get() == fail_at {
                    break;
                }
                let FuzzStmt::Load(load) = &is.stmt else {
                    continue;
                };
                let num_fields = load
                    .state
                    .find_fields_with(|s| crate::utils::is_index_or_length_number(s.ty), true);
                for f in num_fields {
                    let num_loc = Location::new(stmt_index.use_index(), f.clone());
                    let num_op = MutateOperator::new(
                        num_loc.clone(),
                        MutateOperation::IntSet { val: 10000.into() },
                    );
                    let _status = self.execute_with_op(&refined_p, &num_op, false)?;
                    if crash_sig.is_overflow_at_same_rip_or_canary() {
                        return Ok(None);
                    }
                }
            }
            // random mutate other data..
            for _ in 0..256 {
                let mut rand_p = refined_p.clone();
                rand_p.mutate_program_inputs()?;
                let _status = self.executor.execute_program(&rand_p)?;
                if crash_sig.is_overflow_at_same_rip_or_canary() {
                    return Ok(None);
                }
            }
            let f_name = call_stmt.fg.f_name;
            let constraint = Constraint::ArrayLength {
                len: pad_size.into(),
            };
            // padding may luckily avoid the crash but not solve the constraints!
            let new_c = add_function_constraint(
                f_name,
                arg_pos,
                fields,
                constraint,
                &format!(
                    "array should have enough length from crash {} #bug",
                    program.id
                ),
            )?;
            return Ok(new_c);
        }
        Ok(None)
    }
}
