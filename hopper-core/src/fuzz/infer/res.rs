//! Infer resource related constraints
//!
//! APIs that access or allocate limited resources based on argument numbers may encounter resource exhaustion
//! if the number is out of range.
//!
//! If the inputs lead to a timeout or out of memory, we search for large numerical values in the arguments and
//! mutates them. If the execution becomes significantly faster or exits normally after setting the value to be small,
//! we add a RANGE constraint for the argument to limit its maximum value.

use crate::{fuzz::*, fuzzer::*, log, runtime::*, utils};

impl Fuzzer {
    /// Check crash/hang for resource exhaustion
    pub fn crash_infer_resource_exhaustion(
        &mut self,
        program: &FuzzProgram,
        fail_at: usize,
    ) -> eyre::Result<Option<ConstraintSig>> {
        crate::log!(
            trace,
            "start infer resource exhastion due to crash/hang, fail_at: {fail_at}"
        );
        for is in &program.stmts {
            let stmt_index = &is.index;
            if stmt_index.get() == fail_at {
                break;
            }
            let FuzzStmt::Load(load) = &is.stmt else {
                continue;
            };
            let Some((_call_i, call_stmt, arg_pos, prefix)) =
                program.find_stmt_loc_in_all_calls(stmt_index.get(), fail_at)
            else {
                continue;
            };
            let num_fields = load
                .state
                .find_fields_with(|s| utils::is_index_or_length_number(s.ty), true);
            for f in num_fields {
                let loc: Location = Location::new(stmt_index.use_index(), f.clone());
                let val = program.find_number_by_loc(loc.clone())? as i32;
                // underflow for zero
                if val == 0 {
                    if let Some(c) =
                        self.infer_underflow(program, call_stmt, stmt_index, arg_pos, &prefix, &f)?
                    {
                        return Ok(Some(c));
                    }
                }
                // skip if it is not a huge number and it is not a fd
                if val > 8192 || !self.observer.contain_fd(val).0 {
                    let op = MutateOperator::new(loc, MutateOperation::IntSet { val: 16.into() });
                    let status = self.execute_with_op(program, &op, false)?;
                    if !status.is_normal() {
                        crate::log!(trace, "still crash/hang after setting small value");
                        continue;
                    }
                }
                if let Some(c) = self.infer_resource_exhaustion(
                    program, call_stmt, stmt_index, arg_pos, &prefix, &f,
                )? {
                    return Ok(Some(c));
                }
            }
        }
        Ok(None)
    }

    /// Infer numbers that may cause underflow, e.g zero
    fn infer_underflow(
        &mut self,
        program: &FuzzProgram,
        call_stmt: &CallStmt,
        stmt_index: &StmtIndex,
        arg_pos: usize,
        prefix: &LocFields,
        fields: &LocFields,
    ) -> eyre::Result<Option<ConstraintSig>> {
        log!(
            trace,
            "try to infer arg: {arg_pos}, field {fields:?} to be underflow"
        );
        let _ = self.executor.execute_program(program)?;
        let edges = self.observer.feedback.path.get_list();
        let mut huge_loops = vec![];
        for (br, cnt) in edges {
            #[cfg(feature = "fat_bucket")]
            let is_full = if cfg!(feature = "fat_bucket") {
                cnt == 32768
            } else {
                cnt == 128
            };
            if is_full {
                huge_loops.push(br);
            }
        }
        if huge_loops.is_empty() {
            crate::log!(trace, "can't find any huge loop");
            return Ok(None);
        }
        // try to avoid underflow by setting them to other value
        for val in [64, 256, 512] {
            crate::log!(trace, "try to set to be val : {val}");
            let op = MutateOperator::new(
                Location::new(stmt_index.use_index(), fields.clone()),
                MutateOperation::IntSet { val: val.into() },
            );
            let status = self.execute_with_op(program, &op, false)?;
            if status.is_normal() {
                for br in &huge_loops {
                    let cnt = self.observer.feedback.path.buf[*br];
                    if cnt == 0 {
                        // can't find the loop
                        return Ok(None);
                    }
                }
            }
        }
        let full_f = prefix.with_suffix(fields.clone());
        add_function_constraint(
            call_stmt.fg.f_name,
            arg_pos,
            full_f,
            Constraint::NonZero,
            &format!("may be an underflow at crash {} #bug", program.id),
        )
    }

    /// Infer numbers that may exhaust recource, e.g. timeout, OOM
    pub fn infer_resource_exhaustion(
        &mut self,
        program: &FuzzProgram,
        call_stmt: &CallStmt,
        stmt_index: &StmtIndex,
        arg_pos: usize,
        prefix: &LocFields,
        fields: &LocFields,
    ) -> eyre::Result<Option<ConstraintSig>> {
        log!(
            trace,
            "try to infer arg: {arg_pos}, field {fields:?} to be resource-related"
        );
        let f_name = call_stmt.fg.f_name;
        let mut diff_cnt = 0;
        let mut last_num_cmp = 0;
        let mut last_allocated_resources = (0, 0);
        let mut fail_with_huge_number = false;
        let mut path = vec![];
        let start_at = std::time::Instant::now();
        let mut fd_cnt = 0;
        let mut fd_read = false;
        // Try different numbers,
        // and compare how many compares visited in the function.
        // If the #compares and #resource are increasing at most time,
        // It must be loop related.
        for val in [1, 8, 25, 64, 256] {
            let op = MutateOperator::new(
                Location::new(stmt_index.use_index(), fields.clone()),
                MutateOperation::IntSet { val: val.into() },
            );
            let status = self.execute_with_op(program, &op, false)?;
            if status.is_normal() {
                let num_cmp = self.observer.feedback.instrs.cmp_len();
                let allocated_resources = self.observer.feedback.instrs.count_allocated_resources();
                // check fd resource
                let (is_fd, is_fd_read) = self.observer.contain_fd(val);
                if is_fd {
                    fd_cnt += 1;
                    fd_read = is_fd_read;
                }
                crate::log!(
                    trace,
                    "cmp: {num_cmp}, mem: {allocated_resources:?}, fd: {is_fd:?}"
                );
                if num_cmp > last_num_cmp || allocated_resources > last_allocated_resources {
                    diff_cnt += 1;
                }
                last_num_cmp = num_cmp;
                last_allocated_resources = allocated_resources;
                // for the last one
                if val == 512 {
                    path = self.observer.feedback.path.get_list();
                }
            } else {
                // length or array-len?
                return Ok(None);
            }
        }
        crate::log!(trace, "diff_cnt: {diff_cnt}, is_fd_cnt: {fd_cnt}");
        let resource_related = diff_cnt > 4;
        let is_fd = fd_cnt > 4;
        if is_fd {
            let full_f = prefix.with_suffix(fields.clone());
            return add_function_constraint(
                f_name,
                arg_pos,
                full_f,
                Constraint::File {
                    read: fd_read,
                    is_fd: true,
                },
                &format!("infer file fd by diff from program {}", program.id),
            );
        }

        if !resource_related {
            // focus on somthing we can not catch
            // we measure the time and if it crash with huge number
            let loop_secs = start_at.elapsed().as_micros();
            let start_at = std::time::Instant::now();
            // try to set it as the maximal number
            // the program will crash or hang if the number is resource-related or loop-related.
            let op = MutateOperator::new(
                Location::new(stmt_index.use_index(), fields.clone()),
                MutateOperation::IntSet {
                    val: IrEntry::Max(0),
                },
            );
            let status = self.execute_with_op(program, &op, false)?;
            // we simply use crash and timeout to indicate OOM/Timtout here.
            // Since OOM may cause timeout or segment fault(malloc return NULL), killed .. etc.
            // however, it is hard to say that the error is due to the number,
            // e.g if (x > N) { for (int i = 0; i < y; i++) {} }
            // the root cause is `y`'s value, but it will OOM/timeout if we set x to maximal if y is also huge.
            // so we check if the crash path is included by the path before mutating the number.
            if self.observer.feedback.path.is_inclued_by(&path) {
                if status.is_timeout() || status.is_crash() {
                    log!(
                        warn,
                        "loc <{}>{} is fail with huge number",
                        stmt_index.get(),
                        fields.serialize()?
                    );
                    fail_with_huge_number = true;
                }
                let huge_secs = start_at.elapsed().as_micros();
                // if it is too slow with huge number
                if huge_secs > loop_secs * 5 {
                    fail_with_huge_number = true;
                }
            }
        }

        if resource_related || fail_with_huge_number {
            let full_f = prefix.with_suffix(fields.clone());
            let comment = if resource_related {
                format!("infer resource related number from program {}", program.id)
            } else {
                format!("the number should be samll at program {}", program.id)
            };
            // if it has constraints but crash again! we try to make the range samller
            let mut c = Constraint::resource_related();
            let _ = crate::inspect_function_constraint_with(f_name, |fc| {
                if let Some(tc) = fc.arg_constraints[arg_pos]
                .list
                .iter()
                .find(|tc| tc.key == full_f) {
                    if matches!(&tc.constraint, Constraint::Range { min: _, max: _ }) {
                        c = tc.constraint.clone();
                        c.shrink_range();
                    }
                }
                Ok(())
            });

            return add_function_constraint(
                f_name,
                arg_pos,
                full_f,
                c,
                &comment,
            );
        }
        Ok(None)
    }
}
