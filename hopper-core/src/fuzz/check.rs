//! Implement program's functions for checking and finding something

use eyre::ContextCompat;

use crate::{log, runtime::*};

impl FuzzProgram {
    /// Check refer-use relationships in statements
    /// if a statement is not used by any other, it will be deleted.
    pub fn check_ref_use(&mut self) -> eyre::Result<()> {
        let len = self.stmts.len();
        log!(
            trace,
            "start check ref use, len: {}, rng: {:?}",
            self.stmts.len(),
            self.rng
        );
        // log!(trace, "program before check-ref: {}", self.serialize()?);
        for i in (0..len).rev() {
            if let Some(freed) = &self.stmts[i].freed {
                if freed.is_released() {
                    self.stmts[i].freed = None;
                }
            }
            let is = &self.stmts[i];
            match &is.stmt {
                FuzzStmt::Load(_) | FuzzStmt::File(_) => {
                    if is.index.get_ref_used() <= 1 {
                        self.delete_stmt(i);
                    }
                }
                FuzzStmt::Call(call) => {
                    if call.is_relative() {
                        if call.has_reused_args(self).is_none() {
                            self.delete_stmt(i);
                        }
                    } else if !call.is_target() && is.index.get_ref_used() <= 1 {
                        // remove freed, we should remove weak index first
                        for j in 0..i {
                            let is = &mut self.stmts[j];
                            if let Some(f_i) = &is.freed {
                                if !f_i.is_released() && f_i.get() == i {
                                    is.freed = None;
                                }
                            }
                        }
                        self.delete_stmt(i);
                    }
                }
                FuzzStmt::Update(update) => {
                    if let Some(dst_index) = &update.dst.stmt_index {
                        if dst_index.get_ref_used() <= 1 {
                            self.delete_stmt(i);
                        }
                    }
                }
                FuzzStmt::Assert(assert) => {
                    let can_remove = match &assert.rule {
                        AssertRule::NonNull { stmt } => {
                            stmt.is_released() || stmt.get_ref_used() <= 1
                        }
                        AssertRule::Initialized { stmt, call } => {
                            stmt.is_released()
                                || call.is_released()
                                || stmt.get_ref_used() <= 2
                                || !self.check_call_initialize_stmt(stmt.get(), call.get())
                        }
                        AssertRule::Eq { stmt, expected: _ } => {
                            stmt.is_released()
                                || (stmt.get_ref_used() <= 1 && !self.is_target_index(stmt.get()))
                        }
                        AssertRule::Neq { stmt, expected: _ } => {
                            stmt.is_released()
                                || (stmt.get_ref_used() <= 1 && !self.is_target_index(stmt.get()))
                        }
                        _ => false,
                    };
                    if can_remove {
                        self.delete_stmt(i);
                    }
                }
                _ => {}
            }
        }
        self.eliminate_invalidatd_operators();
        self.eliminate_invalidatd_contexts();
        log!(trace, "check ref done: {} -> {}", len, self.stmts.len());

        Ok(())
    }

    /// Check if `index` is target
    fn is_target_index(&self, index: usize) -> bool {
        if let FuzzStmt::Call(call) = &self.stmts[index].stmt {
            return call.is_target();
        }
        false
    }

    /// Eliminate invalidated operators:
    fn eliminate_invalidatd_operators(&mut self) {
        self.ops.retain(|op| !op.key.is_released());
    }

    /// Eliminate invalidated contexts:
    pub fn eliminate_invalidatd_contexts(&mut self) {
        let stmt_uniqs: Vec<u64> = self.stmts.iter().map(|is| is.index.get_uniq()).collect();
        for is in &mut self.stmts {
            if let FuzzStmt::Call(call) = &mut is.stmt {
                call.contexts
                    .retain(|ctx| stmt_uniqs.contains(&ctx.get_uniq()));
            }
            if let Some(i) = &is.freed {
                if i.is_released() || !stmt_uniqs.contains(&i.get_uniq()) {
                    is.freed = None;
                }
            }
        }
    }

    /// The ret of call may change, so we should remove the update once its dst is disappear
    pub fn check_update(&mut self) -> eyre::Result<()> {
        let mut to_delete = vec![];
        for i in (0..self.stmts.len()).rev() {
            let (prev, rest) = self.stmts.split_at_mut(i);
            if let FuzzStmt::Update(update) = &rest[0].stmt {
                let dst_i = update.dst.get_index()?.get();
                if let FuzzStmt::Call(call) = &mut prev[dst_i].stmt {
                    let found = call.ret_ir.iter_mut().find(|ir| {
                        if ir.fields == update.dst.fields {
                            return true;
                        }
                        if let Some(f) = update.dst.fields.list.strip_prefix(&ir.fields.list[..]) {
                            return ir.state.get_child_by_fields(f).is_ok();
                        }
                        false
                    });
                    if let Some(ir) = found {
                        ir.used = Some(rest[0].index.downgrade());
                    } else {
                        // can't find the ir, need remove
                        crate::log!(
                            trace,
                            "can't find {:?} in call ret_ir, remove update: {}",
                            &update.dst,
                            i
                        );
                        to_delete.push(i);
                    }
                }
            }
        }
        if !to_delete.is_empty() {
            for i in to_delete {
                let _stmt = self.stmts.remove(i);
            }
            self.resort_indices();
            self.check_ref_use()?;
        }
        Ok(())
    }

    /// Get depth of stub stmt,
    /// used for provide properties for mutating
    pub fn get_stub_stmt_depth(&self) -> eyre::Result<usize> {
        let index = self.get_stub_stmt_index().context("can't find stub")?;
        let depth = get_stmt_depth(index.get(), self);
        Ok(depth)
    }

    /// If the opaque pointer has been inited in the program
    pub fn has_been_inited(&self, opaque_ptr: &StmtIndex) -> Option<usize> {
        for is in self.stmts[opaque_ptr.get()..].iter() {
            if let FuzzStmt::Assert(assert) = &is.stmt {
                if let AssertRule::Initialized { stmt, call } = &assert.rule {
                    if stmt.get() == opaque_ptr.get() {
                        return Some(call.get());
                    }
                }
            }
        }
        None
    }

    /// check if call is used to initialize the statement
    pub fn check_call_initialize_stmt(&self, stmt: usize, call: usize) -> bool {
        if let FuzzStmt::Call(cur_call) = &self.stmts[call].stmt {
            if cur_call.is_related_call_for_ptee(stmt, self) {
                return true;
            }
        }
        false
    }

    /// If the location is a null pointer
    pub fn is_loc_null(&self, loc: &Location) -> bool {
        let index = loc.get_index().unwrap().get();
        if let FuzzStmt::Load(load) = &self.stmts[index].stmt {
            match load.state.get_child_by_fields(loc.fields.as_slice()) {
                Ok(state) => {
                    if let Some(c) = state.children.first() {
                        return c.is_null();
                    }
                    return state.is_null();
                }
                Err(crate::HopperError::UnionErr) => {
                    return false;
                }
                Err(he) => unreachable!(
                    "unable to handle `{he:?}` in is_loc_null, p: \n{self}\nloc:{loc:?}",
                ),
            }
        }
        false
    }

    /// Check if it is file or not
    pub fn is_file_loc(&self, loc: &Location) -> bool {
        if loc.is_null() {
            return false;
        }
        let dst_stmt = &self.stmts[loc.get_index().unwrap().get()].stmt;
        if loc.fields.is_empty() && matches!(dst_stmt, FuzzStmt::File(_)) {
            return true;
        }
        if let FuzzStmt::Load(load) = dst_stmt {
            match load.state.get_child_by_fields(loc.fields.as_slice()) {
                Ok(state) => {
                    if let Some(ps) = state.pointer.as_ref() {
                        if let Some(stmt_index) = ps.pointer_location.stmt_index.as_ref() {
                            return matches!(&self.stmts[stmt_index.get()].stmt, FuzzStmt::File(_));
                        }
                    }
                }
                Err(crate::HopperError::UnionErr) => {
                    return false;
                }
                Err(he) => unreachable!(
                    "unable to handle `{he:?}` in is_file_loc, p: \n{self}\nloc:{loc:?}",
                ),
            }
        }
        false
    }

    /// Check if the loc is mutated
    pub fn is_loc_mutated(&self, loc: &Location) -> bool {
        let wl = loc.to_weak_loc();
        self.ops.iter().any(|l| !l.key.is_released() && l.key == wl)
    }
}

/// get depth of current statement
fn get_stmt_depth(index: usize, program: &FuzzProgram) -> usize {
    let mut depth = 0;
    let mut cur = index;
    for is in &program.stmts[index..] {
        match &is.stmt {
            FuzzStmt::Call(call) => {
                if call.args.iter().any(|i| i.get() == cur) {
                    depth += 1;
                    cur = is.index.get();
                }
            }
            FuzzStmt::File(file) => {
                if let Some(i) = &file.buf_stmt {
                    if i.get() == cur {
                        cur = is.index.get();
                    }
                }
            }
            FuzzStmt::Update(update) => {
                if update.src.get() == cur {
                    cur = update.dst.get_index().unwrap().get();
                }
            }
            FuzzStmt::Load(load) => {
                if load
                    .state
                    .find_any_stmt_in_state_with(|ptee| ptee.get() == cur)
                {
                    depth += 1;
                    cur = is.index.get();
                }
            }
            _ => {}
        }
    }
    depth
}

#[test]
fn test_program_detph() {
    let mut p = FuzzProgram::default();
    let load_index = p.append_stmt(LoadStmt::new(
        Box::new(0_u8),
        LoadStmt::new_state("val", ""),
    ));
    let mut ptr_state = LoadStmt::new_state("ptr", "");
    let ptr = crate::FuzzMutPointer::<u8>::loc_pointer(&mut ptr_state, Location::stmt(load_index));
    let ptr_index = p.append_stmt(LoadStmt::new(Box::new(ptr), ptr_state));
    let fg = global_gadgets::get_instance()
        .get_func_gadget("func_add")
        .unwrap()
        .clone();
    let mut call = CallStmt::new("call".to_string(), "func_add".to_string(), fg);
    call.set_arg(0, ptr_index);
    let _call_index = p.append_stmt(call);
    assert_eq!(get_stmt_depth(0, &p), 2);
    assert_eq!(get_stmt_depth(1, &p), 1);
    assert_eq!(get_stmt_depth(2, &p), 0);
}
