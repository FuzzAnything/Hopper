//! Infer non zero constraint for SIGFPE

use crate::{fuzz::*, fuzzer::*, runtime::*, utils};

impl Fuzzer {
    /// Infer SIGFPE, find division by zero errors.
    pub fn infer_sigfpe(
        &mut self,
        program: &FuzzProgram,
        _call_i: usize,
        call_stmt: &CallStmt,
        stmt_index: &StmtIndex,
        load_state: &ObjectState,
        arg_pos: usize,
        prefix: LocFields,
        last_cmps: &[u32],
    ) -> eyre::Result<Option<ConstraintSig>> {
        crate::log!(
            trace,
            "infer division by zero error for sigfpe, stmt: {}!",
            stmt_index.get()
        );
        // hash?
        let num_fields =
            load_state.find_fields_with(|s| utils::is_index_or_length_number(s.ty), true);
        for f in num_fields {
            // if it is zero
            let num_loc = Location::new(stmt_index.use_index(), f.clone());
            let num = program.find_number_by_loc(num_loc.clone())?;
            if num == 0 {
                crate::log!(trace, "find zero number: {num_loc:?}");
                let op = MutateOperator::new(num_loc, MutateOperation::IntSet { val: 1.into() });
                let status = self.execute_with_op(program, &op, false)?;
                if !status.is_sigfpe()
                    && self.observer.feedback.instrs.contain_cmp_chunks(last_cmps)
                {
                    let full_f = prefix.with_suffix(f.clone());
                    let sig = add_function_constraint(
                        call_stmt.fg.f_name,
                        arg_pos,
                        full_f,
                        Constraint::NonZero,
                        &format!("infer non_zero for sigfpe in crash {} #bug", program.id),
                    );
                    return sig;
                }
            }
        }
        Ok(None)
    }
}
