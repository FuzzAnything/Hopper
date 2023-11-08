//! Implement program's functions for finding something

use crate::{log, runtime::*, fuzz::*};

impl FuzzProgram {
    /// Get number's value by loc
    pub fn find_number_by_loc(&self, loc: Location) -> eyre::Result<u64> {
        let op = MutateOperator::new(loc, MutateOperation::IntGet);
        let mut ptmp = self.clone();
        ptmp.mutate_program_by_op(&op)?;
        Ok(flag::get_tmp_u64())
    }

    /// Find length entry in all calls' arguments
    pub fn find_stmt_loc_in_all_calls(
        &self,
        target_index: usize,
        max: usize,
    ) -> Option<(usize, &CallStmt, usize, LocFields)> {
        for call_i in (0..=max).rev() {
            if let FuzzStmt::Call(call_stmt) = &self.stmts[call_i].stmt {
                if let Some((arg_pos, prefix)) =
                    self.find_stmt_loc_for_call(target_index, &call_stmt.args)
                {
                    return Some((call_i, call_stmt, arg_pos, prefix));
                }
            }
        }
        None
    }

    /// Find stmt in call's arguments
    pub fn find_stmt_loc_for_call(
        &self,
        target_index: usize,
        call_args: &[StmtIndex],
    ) -> Option<(usize, LocFields)> {
        for (arg_pos, arg_stmt) in call_args.iter().enumerate() {
            let field = LocFields::default();
            if arg_stmt.get() == target_index {
                return Some((arg_pos, field));
            }
            let ret = self.find_stmt_loc_for_stmt(target_index, arg_stmt, &field);
            if let Some(f) = ret {
                return Some((arg_pos, f));
            }
        }
        None
    }

    /// Return the fields that how to get the `target_index` inside `root_stmt`
    fn find_stmt_loc_for_stmt(
        &self,
        target_index: usize,
        root_stmt: &StmtIndex,
        prefix: &LocFields,
    ) -> Option<LocFields> {
        match &self.stmts[root_stmt.get()].stmt {
            FuzzStmt::Load(load) => {
                let mut st = vec![&load.state];
                while let Some(s) = st.pop() {
                    if let Some(ptee_stmt) = s.get_pointer_stmt_index() {
                        let mut sub_prefix = prefix.with_suffix(s.get_location_fields());
                        sub_prefix.push(FieldKey::Pointer);
                        if ptee_stmt.get() == target_index {
                            return Some(sub_prefix);
                        }
                        let ret = self.find_stmt_loc_for_stmt(
                            target_index,
                            ptee_stmt,
                            &sub_prefix,
                        );
                        if ret.is_some() {
                            return ret;
                        }
                    }
                    for sub_state in s.children.iter() {
                        st.push(sub_state);
                        // only consider first element for sequence
                        if sub_state.children.is_empty() {
                            if let FieldKey::Index(_) = sub_state.key {
                                break;
                            }
                        }
                    }
                }
            }
            FuzzStmt::Call(_call_stmt) => {
                for is in &self.stmts[root_stmt.get()..] {
                    if let FuzzStmt::Update(update_stmt) = &is.stmt {
                        if let Some(dst_index) = update_stmt.dst.stmt_index.as_ref() {
                            if update_stmt.src.get() == target_index
                                && dst_index.get_uniq() == root_stmt.get_uniq()
                            {
                                let mut dst_fields = update_stmt.dst.fields.clone();
                                // remove duplicated pointer fieldkey
                                dst_fields.strip_pointer_suffix();
                                if dst_fields.list.first() == Some(&FieldKey::Pointer) {
                                    dst_fields.pop();
                                }
                                let sub_prefix = prefix.with_suffix(dst_fields);
                                log!(trace, "update prefix: {sub_prefix:?}");
                                return Some(sub_prefix);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }
}
