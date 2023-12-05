use eyre::{Context, ContextCompat};

use crate::{fuzzer::Fuzzer, runtime::*, utils, StatusType, MutateOperation};

impl Fuzzer {
    /// Minimize the program before save
    /// 
    // TODO: for fast executions, we can find all prev programs and view them as one, and try to minimize it.
    pub fn minimize(
        &mut self,
        program: &mut FuzzProgram,
        ori_status: &StatusType,
    ) -> eyre::Result<bool> {
        // ignore det mutation
        if let Some(op) = program.ops.first() {
            if op.det && !matches!(op.op, MutateOperation::BufSeed { .. }) {
                return Ok(false);
            }
        }
        let start_at = std::time::Instant::now();
        let original_len = program.stmts.len();
        let hash = self.observer.feedback.path.hash_trace();
        let prev_cnt = self.count;
        crate::log!(trace, "try minimize input, hash: {hash}");
        // try to minimize operators
        let mut changed = self
            .minimize_ops(program, hash, ori_status)
            .context(format!("program: {}", program.serialize_all().unwrap()))?;
        let mut visited = vec![];
        loop {
            let mut p = program.clone();
            if !p.try_minimize(&mut visited)? {
                break;
            }
            let status = self.executor.execute_program(&p)?;
            self.count += 1;
            if &status == ori_status {
                let cur_hash = self.observer.feedback.path.hash_trace();
                crate::log!(trace, "cur_hash: {cur_hash}");
                // ok, we adapt this minimization
                if cur_hash == hash {
                    crate::log!(trace, "hash is the same, keep mutation");
                    changed = true;
                    program.ops = program.ops.clone_with_program(&mut p);
                    program.stmts = p.stmts;
                }
            }
            // rollback and skip it then
        }
        if changed {
            // refine again
            program.refine_program()?;
            program.ops.retain(|op| !op.key.is_released());
            crate::log!(
                trace,
                "minimize program, #stmts {original_len} -> {}, hash: {hash}!",
                program.stmts.len()
            );
        }
        let cnt = self.count - prev_cnt;
        let secs = start_at.elapsed().as_secs_f32();
        crate::log!(trace, "try {cnt} minimize uses {secs} seconds");
        Ok(changed)
    }

    fn minimize_ops(
        &mut self,
        program: &mut FuzzProgram,
        hash: u64,
        ori_status: &StatusType,
    ) -> eyre::Result<bool> {
        if program.ops.len() <= 1 {
            return Ok(false);
        }
        let mut changed = false;
        crate::log!(trace, "try minimize mutate ops");
        let parent_id = program
            .parent
            .context("can't find parent for mutated program")?;
        let parent = if let Some(p) = self.depot.get_program_by_id(parent_id) {
            p.clone()
        } else {
            crate::read_input_in_queue(parent_id)?
        };
        let mut ops = program.ops.clone();
        for op_i in (0..ops.len()).rev() {
            crate::log!(trace, "try remove op: {op_i}");
            let op = ops.remove(op_i);
            let mut p = parent.clone();
            p.mutate_program_by_ops(&ops)?;
            p.refine_program()?;
            let status = self.executor.execute_program(&p)?;
            self.count += 1;
            crate::log!(trace, "status: {ori_status:?} vs. {status:?}");
            if &status == ori_status {
                let cur_hash = self.observer.feedback.path.hash_trace();
                crate::log!(trace, "hash: {cur_hash} vs. {hash}");
                if cur_hash == hash {
                    changed = true;
                    program.stmts = p.stmts;
                    program.ops = p.ops;
                    continue;
                }
            }
            // insert back
            ops.insert(op_i, op);
        }
        Ok(changed)
    }
}

impl FuzzProgram {
    // Try minimize Program
    pub fn try_minimize(&mut self, visited: &mut Vec<u64>) -> eyre::Result<bool> {
        let len = self.stmts.len();
        for i in (0..len).rev() {
            let is = &mut self.stmts[i];
            let uniq = is.index.get_uniq();
            if visited.contains(&uniq) {
                continue;
            }
            match &mut is.stmt {
                FuzzStmt::Load(load) => {
                    // set vec to smaller: 1
                    let len = load.value.get_length();
                    if len > 1 && utils::is_vec_type(load.value.type_name()) {
                        // craft an uniq number for this
                        let sub_uniq = uniq * 2 + len as u64;
                        if visited.contains(&sub_uniq) {
                            continue;
                        }
                        visited.push(sub_uniq);
                        crate::log!(trace, "try delete length {} to {}", len, len / 2);
                        load.value.mutate_by_op(
                            &mut load.state,
                            &[],
                            &crate::MutateOperation::VecDel {
                                offset: 1,
                                len: len / 2,
                            },
                        )?;
                        // we should refine length/range constraints
                        self.refine_program()?;
                        return Ok(true);
                    }
                    // try to set null
                    let non_null_fields = load.state.find_fields_with(|s| s.is_non_null(), false);
                    for f in non_null_fields {
                        // craft a uniq hash
                        let sub_uniq = uniq + crate::hash_buf(f.serialize()?.as_bytes());
                        if visited.contains(&sub_uniq) {
                            continue;
                        }
                        visited.push(sub_uniq);
                        let sub_state = load.state.get_child_mut_by_fields(f.as_slice())?;
                        if let Some(ps) = sub_state.pointer.as_mut() {
                            crate::log!(trace, "try set pointer to null: {f:?}");
                            ps.pointer_location = Location::null();
                            self.check_ref_use()?;
                            return Ok(true);
                        }
                    }
                }
                FuzzStmt::Call(call) => {
                    // TODO: if the call is marked as track, remove it must affect the path
                    // if call.track_cov {
                    //    visited.push(uniq);
                    //     return Ok(true);
                    // }
                    if !crate::config::ENABLE_INTER_API_LEARN
                        || !(call.is_implicit() || call.is_relative())
                    {
                        continue;
                    }
                    crate::log!(trace, "try remove context: {i}");
                    self.delete_stmt(i);
                    self.check_ref_use()?;
                    visited.push(uniq);
                    return Ok(true);
                }
                _ => {}
            }
            visited.push(uniq);
        }
        Ok(false)
    }
}
