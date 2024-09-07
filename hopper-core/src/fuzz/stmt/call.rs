//! Mutate call statments
//! Including:
//!  - mutate call function's arguments
//!  - mutate call function's return value
//!  - insert or delete functions that has implicit relationships

use crate::{config, utils};

use super::*;

impl WeightedItem for CallStmt {
    fn get_weight(&self) -> usize {
        // since the search space of call is limited compared to load,
        // we set it to 1, the minimal weight.
        1
    }
}

impl StmtMutate for CallStmt {
    fn is_incompatible(&self, _op: &MutateOperator) -> bool {
        // mutate call statement is incompatible
        true
    }

    fn mutate_by_op(
        &mut self,
        program: &mut FuzzProgram,
        _keys: &[FieldKey],
        op: &MutateOperation,
    ) -> eyre::Result<()> {
        let depth = program.get_stub_stmt_depth()?;
        match op {
            MutateOperation::CallArg { arg_pos, rng_state } => {
                let _tmp_rng = rng::TempRngGuard::temp_use(rng_state);
                self.set_ith_call_arg(program, *arg_pos, depth)?;
            }
            MutateOperation::EffCallArg {
                arg_pos,
                eff_i: _,
                rng_state,
            } => {
                let _tmp_rng = rng::TempRngGuard::temp_use(rng_state);
                let _ = self.set_effective_ith_call_arg(program, *arg_pos, depth)?;
            }
            MutateOperation::CallImplicitInsert { f_name, rng_state } => {
                let _tmp_rng = rng::TempRngGuard::temp_use(rng_state);
                self.insert_implicit_call_with(program, f_name, depth)?;
            }
            MutateOperation::CallRelatedInsert {
                f_name: _,
                arg_pos,
                rng_state,
            } => {
                let _tmp_rng = rng::TempRngGuard::temp_use(rng_state);
                self.insert_relative_call_for_ith_arg(program, *arg_pos, depth, false)?;
            }
            MutateOperation::NewTarget { f_name, arg_i } => {
                if let Some(arg_i) = arg_i {
                    self.append_new_target_with_arg(program, depth, f_name, *arg_i)?;
                } else {
                    self.append_new_target_with_context(program, depth, f_name)?;
                }
            }
            MutateOperation::Nop => {}
            _ => {
                crate::log!(trace, "ignore op: {op:?} in call stmt");
            }
        }
        Ok(())
    }

    fn mutate(&mut self, program: &mut FuzzProgram) -> eyre::Result<MutateOperator> {
        // mutate call should be incompatible with other mutations
        if !program.ops.is_empty() || flag::is_single_call() {
            return Ok(MutateOperator::nop());
        }
        let depth = program.get_stub_stmt_depth()?;

        for _ in 0..4 {
            let op = if self.is_leaf() {
                match rng::gen_range(0..=5) {
                    0..=2 => self.insert_relative_call_before(program, depth)?,
                    3 => self.insert_implicit_call_before(program, depth)?,
                    4 => self.random_replace_arg(program, depth)?,
                    5 => {
                        if config::ENABLE_APPEND_NEW_TARGET && self.is_target() {
                            self.choose_new_target_and_append(program, depth)?
                        } else {
                            MutateOperator::nop()
                        }
                    }
                    _ => {
                        unimplemented!()
                    }
                }
            } else {
                // arguments
                match rng::gen_range(0..=3) {
                    0 => self.insert_relative_call_before(program, depth)?,
                    1 => self.insert_implicit_call_before(program, depth)?,
                    2 => update::append_update_stmt(program, self)?,
                    3 => self.random_replace_arg(program, depth)?,
                    _ => {
                        unimplemented!()
                    }
                }
            };
            if op.is_nop() {
                crate::log!(trace, "fail to mutate call, continue");
                // remove those useless statments imposed by current mutation
                program.check_ref_use()?;
                continue;
            }
            return Ok(op);
        }

        crate::log!(trace, "fail to mutate call, break");
        Ok(MutateOperator::nop())
    }

    fn is_deterministic(&self) -> bool {
        if !is_call_det() {
            return false;
        }
        let det_index = *self.det_index.borrow();
        let len = global_gadgets::get_instance().functions.len();
        crate::log!(trace, "call is_det: {det_index}, len: {len}");
        self.is_target() && det_index < len
    }

    fn det_mutate(&mut self, program: &mut FuzzProgram) -> eyre::Result<MutateOperator> {
        // avoid try context again and again
        // we only use it in mutating seed program that generated from nothing
        if program.parent != Some(program.id) {
            self.det_index.replace(usize::MAX);
            return Ok(MutateOperator::nop());
        }
        // add different context
        let det_index = *self.det_index.borrow();
        let depth = program.get_stub_stmt_depth()?;
        let gadgets = global_gadgets::get_instance();
        for (i, fg) in gadgets.functions.values().enumerate() {
            self.det_index.replace(i + 1);
            if i < det_index
                || fg.f_name == self.name
                || !filter_function(fg.f_name)
                || self.has_any_context(program, fg.f_name)
            {
                continue;
            }
            let f_name = fg.f_name.to_string();
            for arg_pos in 0..self.args.len() {
                if let Some(related_arg_pos) = check_relative_argument(&self.fg, fg, arg_pos, false)
                {
                    let rng_state = rng::save_rng_state();
                    crate::log!(trace, "det mutate call: {det_index}-th: relative, {f_name}");
                    if self.insert_relative_call_for_ith_arg_with(
                        program,
                        arg_pos,
                        depth,
                        false,
                        fg,
                        related_arg_pos,
                    )? {
                        return Ok(MutateOperator::stmt_op(
                            MutateOperation::CallRelatedInsert {
                                f_name,
                                arg_pos,
                                rng_state,
                            },
                        ));
                    } else {
                        return Ok(MutateOperator::nop());
                    }
                }
            }
            // if has lots APIs, we skip det-steps for implicit call insertion.
            if gadgets.functions.len() > 80 {
                continue;
            }
            let rng_state = rng::save_rng_state();
            crate::log!(
                trace,
                "det mutate call: {det_index}-th: implicit, {}",
                fg.f_name
            );
            self.insert_implicit_call_with(program, fg.f_name, depth)?;
            return Ok(MutateOperator::stmt_op(
                MutateOperation::CallImplicitInsert { f_name, rng_state },
            ));
        }
        Ok(MutateOperator::nop())
    }
}

impl CallStmt {
    /// Genrate function call for `f_name` in `program`
    pub fn generate_new(
        program: &mut FuzzProgram,
        ident: &str,
        f_name: &str,
        depth: usize,
    ) -> eyre::Result<Self> {
        let fg = global_gadgets::get_instance()
            .get_func_gadget(f_name)?
            .clone();
        let mut call = CallStmt::new(ident.to_string(), f_name.to_string(), fg);
        // Find or create args for call
        let type_names = call.fg.arg_types;
        let is_variadic = utils::is_variadic_function(type_names);
        let num_arg = if is_variadic {
            type_names.len() - 1
        } else {
            type_names.len()
        };

        for arg_pos in 0..num_arg {
            call.set_ith_call_arg(program, arg_pos, depth)?;
        }

        for arg_pos in 0..num_arg {
            // only for primitive type
            if rng::coin() {
                let arg_type = call.fg.arg_types[arg_pos];
                if utils::is_primitive_type(arg_type) || utils::is_buffer_pointer(arg_type) {
                    let _ = call.set_effective_ith_call_arg(program, arg_pos, depth)?;
                }
            }
        }

        // We must add these required contexts
        call.add_required_contexts(program, depth)?;

        // try to generate context in generate mode
        // #[cfg(not(test))]
        if !flag::is_single_call() && call.is_target() && program.parent.is_none() && rng::likely()
        {
            if rng::rarely() {
                let _op = call.insert_implicit_call_before(program, depth)?;
            } else {
                let _op = call.insert_relative_call_before(program, depth)?;
            }
        }

        Ok(call)
    }

    /// Find or create ith argument
    pub fn set_ith_call_arg(
        &mut self,
        program: &mut FuzzProgram,
        arg_pos: usize,
        depth: usize,
    ) -> eyre::Result<()> {
        let ident = self.fg.arg_idents[arg_pos];
        let type_name = self.fg.arg_types[arg_pos];
        let alias_type_name = self.fg.alias_arg_types[arg_pos];
        crate::log!(
            trace,
            "generate {arg_pos}-th arg, type: {type_name} ({alias_type_name}), ident: {ident}, depth: {depth}, single: {}",
            flag::is_single_call()
        );
        let mut non_null = false;
        let mut need_init = false;
        // 0. if the argument has any constraint
        let should_ret = inspect_function_constraint_with(self.fg.f_name, |fc| {
            if !config::ENABLE_REFINE {
                return Ok(false);
            }
            for citem in fc.arg_constraints[arg_pos].list.iter() {
                if !citem.key.is_empty() {
                    continue;
                }
                match &citem.constraint {
                    Constraint::SetNull => {
                        let null_stmt = LoadStmt::generate_constant(type_name, ident)?;
                        let stmt_index = program.insert_or_append_stmt(null_stmt)?;
                        self.set_arg(arg_pos, stmt_index);
                        return Ok(true);
                    }
                    Constraint::File { read, is_fd } => {
                        let (is_c_str, is_mut) = utils::is_c_str_type(type_name);
                        if is_c_str {
                            let read = *read;
                            let is_fd = *is_fd;
                            let file_stmt =
                                FileStmt::generate_new(program, ident, is_mut, is_fd, read, depth)?;
                            crate::log!(
                                trace,
                                "generate file for arg `{ident}` in function `{}`",
                                self.name
                            );
                            let stmt_index = program.insert_or_append_stmt(file_stmt)?;
                            self.set_arg(arg_pos, stmt_index);
                            return Ok(true);
                        }
                    }
                    Constraint::RetFrom { ret_f } => {
                        let ret_f = ret_f.clone();
                        self.insert_call_as_arg(program, arg_pos, type_name, &ret_f, ident, depth)?;
                        return Ok(true);
                    }
                    /* 
                    Constraint::CastFrom { cast_type } => {
                        // make sure it is pointer
                        eyre::ensure!(
                            utils::is_pointer_type(type_name),
                            "cast type should be a pointer"
                        );
                        // modify type_name, and alias_type
                        type_name = utils::get_static_ty(cast_type);
                        // alias_type_name = type_name;
                    }
                    */
                    Constraint::SetVal { val: _ } | Constraint::Range { min: _, max: _ } => {
                        // avoid create calls
                        let load = LoadStmt::generate_new(program, type_name, ident, depth)?;
                        let load_index = program.insert_or_append_stmt(load)?;
                        self.set_arg(arg_pos, load_index);
                        return Ok(true);
                    }
                    Constraint::NonNull => {
                        non_null = true;
                    }
                    Constraint::NeedInit => {
                        need_init = true;
                    }
                    _ => {}
                }
            }
            Ok(false)
        })?;

        if should_ret {
            return Ok(());
        }

        let is_opaque = utils::is_opaque_pointer(type_name);

        // 1. use other statement
        // if the prorgam has any existing statement that provide such types.
        if ((flag::is_reuse_stmt()
            && rng::coin()
            // avoid cause circle-refs
            && self
                .has_reused_args(program)
                .map_or(true, |pos| pos == arg_pos))
            || is_opaque)
            && !self.is_implicit()
        {
            if let Some(stmt_index) = find_stmts_with_type(program, ident, type_name, &self.args) {
                crate::log!(trace, "use stmt `{}` as arg ", stmt_index.get());
                self.set_arg(arg_pos, stmt_index);
                return Ok(());
            }
        }

        // 2. find new function and insert call to provide the argument.
        // we only find return for pointer types
        if let Some(inner) = utils::get_pointer_inner(type_name) {
            if flag::use_call(inner, is_opaque, depth)
                || (is_opaque && depth <= config::MAX_DEPTH && non_null)
            {
                if let Some(provider) = find_func_with_return_type(type_name, alias_type_name) {
                    if provider != self.fg.f_name {
                        self.insert_call_as_arg(
                            program, arg_pos, type_name, provider, ident, depth,
                        )?;
                        return Ok(());
                    }
                }
            }
        }

        // 3. if we can't find any function or statement, generate load directly
        crate::log!(trace, "load new `{type_name}` as arg, opaque: {is_opaque} ");
        let load = LoadStmt::generate_new(program, type_name, ident, depth)?;
        let is_null_ptr = load.state.is_null();
        let load_index = program.insert_or_append_stmt(load)?;
        self.set_arg(arg_pos, load_index);

        // if the arg is opaque pointer, we should try to init it
        if is_null_ptr
            && is_opaque
            && depth <= config::MAX_DEPTH
            && (need_init || rng::coin() || flag::is_pilot_det())
        {
            crate::log!(trace, "try to init opaque by relative call");
            let op = self.insert_relative_call_for_ith_arg(program, arg_pos, depth, true)?;
            if op.is_nop() {
                crate::log!(trace, "fail to init opaque pointer");
            }
        }

        Ok(())
    }

    /// Add all required contexts
    fn add_required_contexts(
        &mut self,
        program: &mut FuzzProgram,
        depth: usize,
    ) -> eyre::Result<()> {
        let mut use_contexts = vec![];
        filter_function_constraint_with(&self.name, |fc| {
            let iter = fc
                .contexts
                .iter()
                .filter(|ctx| ctx.is_required() && !self.has_any_context(program, &ctx.f_name));
            use_contexts.extend(iter.cloned());
            true
        });
        for ctx in use_contexts {
            crate::log!(trace, "try to insert required relative context: {ctx:?}");
            // relative contexts
            if let Some(arg_pos) = ctx.related_arg_pos {
                let fg = global_gadgets::get_instance().get_func_gadget(&ctx.f_name)?;
                if let Some(f_i) = check_relative_argument(&self.fg, fg, arg_pos, false) {
                    self.insert_relative_call_for_ith_arg_with(
                        program, arg_pos, depth, false, fg, f_i,
                    )?;
                }
            } else {
                // implicit contexts
                self.insert_implicit_call_with(program, &ctx.f_name, depth)?;
            }
        }
        Ok(())
    }

    /// Insert call for `index`-th argument
    fn insert_call_as_arg(
        &mut self,
        program: &mut FuzzProgram,
        arg_pos: usize,
        arg_type: &str,
        f_name: &str,
        ident: &str,
        depth: usize,
    ) -> eyre::Result<()> {
        crate::log!(trace, "use call `{}` as arg ", f_name);
        let _tmp = flag::ReuseStmtGuard::temp_disable();
        let call = CallStmt::generate_new(program, ident, f_name, depth + 1)?;
        let call_index = program.insert_or_append_stmt(call)?;
        let _ = program.insert_or_append_stmt(AssertStmt::assert_non_null(call_index.use_index()));
        // arg's replace will mutate the pointer to new one, so we make it constant here.s
        let mut ptr_load = LoadStmt::generate_constant(arg_type, ident)?;
        let mut loc = Location::stmt(call_index);
        loc.fields.push(FieldKey::Pointer);
        ptr_load.state.get_pointer_mut()?.pointer_location = loc;
        let ptr_index = program.insert_or_append_stmt(ptr_load)?;
        self.set_arg(arg_pos, ptr_index);
        Ok(())
    }

    /// Random replace call's argument
    fn random_replace_arg(
        &mut self,
        program: &mut FuzzProgram,
        depth: usize,
    ) -> eyre::Result<MutateOperator> {
        if self.args.is_empty() || self.is_relative() {
            return Ok(MutateOperator::nop());
        }

        /*
        // avoid replace arguments that related
        let has_related = filter_function_constraint_with(self.fg.f_name, |fc| {
            !fc.get_related_args(arg_pos).is_empty()
        });
        if has_related || self.args[arg_pos].get_ref_used() > 2 {
            return Ok(MutateOperator::nop());
        }
        */
        let mut op = MutateOperation::Nop;
        if rng::coin() {
            let mut arg_indices: Vec<usize> = (0..self.args.len()).collect();
            // make the order randomly
            rng::shuffle(&mut arg_indices);
            let rng_state = rng::save_rng_state();
            for arg_pos in arg_indices {
                if let Some(eff_i) = self.set_effective_ith_call_arg(program, arg_pos, depth)? {
                    op = MutateOperation::EffCallArg {
                        arg_pos,
                        eff_i,
                        rng_state,
                    };
                    break;
                }
            }
        }
        if op.is_nop() {
            let arg_pos = rng::gen_range(0..self.args.len());
            crate::log!(trace, "try to replace arg-{arg_pos}");
            let rng_state = rng::save_rng_state();
            self.set_ith_call_arg(program, arg_pos, depth)?;
            op = MutateOperation::CallArg { arg_pos, rng_state };
        }
        Ok(MutateOperator::stmt_op(op))
    }

    fn choose_new_target_and_append(
        &mut self,
        program: &mut FuzzProgram,
        depth: usize,
    ) -> eyre::Result<MutateOperator> {
        if depth > config::MAX_DEPTH {
            return Ok(MutateOperator::nop());
        }
        let gadgets: &ProgramGadgets = global_gadgets::get_instance();
        if let Some(inner_ty) = self
            .fg
            .ret_type
            .filter(|_| {
                crate::filter_function_constraint_with(self.fg.f_name, |fc| fc.can_used_as_arg())
            })
            .and_then(utils::get_pointer_inner)
        {
            // FIXME: check ret_type is not static and writeable?
            // `self` is used as arg of new target
            if flag::use_call(inner_ty, utils::is_opaque_type(inner_ty), depth) {
                let mut_ptr = utils::mut_pointer_type(inner_ty);
                let mut_iter: &[(&str, usize)] = gadgets
                    .arg_graph
                    .get(mut_ptr.as_str())
                    .map_or(&[], |l| l.as_slice());
                let const_ptr = utils::const_pointer_type(inner_ty);
                let const_iter: &[(&str, usize)] = gadgets
                    .arg_graph
                    .get(const_ptr.as_str())
                    .map_or(&[], |l| l.as_slice());
                let iter = mut_iter
                    .iter()
                    .chain(const_iter)
                    .filter(|(f_name, _)| filter_target_function(f_name));
                if let Some((f_name, arg_i)) = rng::choose_iter(iter) {
                    self.append_new_target_with_arg(program, depth, f_name, *arg_i)?;
                    return Ok(MutateOperator::stmt_op(MutateOperation::NewTarget {
                        f_name: f_name.to_string(),
                        arg_i: Some(*arg_i),
                    }));
                }
            }
        }
        // `self` is relative to new target.
        let funcs = global_gadgets::get_instance()
            .functions
            .iter()
            .filter(|(f_name, _)| filter_target_function(f_name));
        if let Some((f_name, _)) = rng::choose_iter(funcs) {
            self.append_new_target_with_context(program, depth, f_name)?;
            return Ok(MutateOperator::stmt_op(MutateOperation::NewTarget {
                f_name: f_name.to_string(),
                arg_i: None,
            }));
        }

        Ok(MutateOperator::nop())
    }

    fn append_new_target_with_arg(
        &mut self,
        program: &mut FuzzProgram,
        depth: usize,
        f_name: &str,
        arg_i: usize,
    ) -> eyre::Result<()> {
        crate::log!(trace, "append new target : {f_name} and its arg: {arg_i}");
        let mut new_call = CallStmt::generate_new(program, CallStmt::TARGET, f_name, depth + 1)?;
        program.set_calls_track_cov(false);
        new_call.track_cov = true;
        let arg_type = new_call.fg.arg_types[arg_i];
        let prev_target_index = program.get_stub_stmt_index().unwrap();
        let _ = program.append_stmt(AssertStmt::assert_non_null(prev_target_index.use_index()));
        self.track_cov = false;
        self.ident = new_call.fg.arg_idents[arg_i].to_string();
        if utils::is_pointer_type(arg_type) {
            let mut ptr_load = LoadStmt::generate_constant(arg_type, &self.ident)?;
            let mut loc = Location::stmt(prev_target_index);
            loc.fields.push(FieldKey::Pointer);
            ptr_load.state.get_pointer_mut()?.pointer_location = loc;
            let ptr_index = program.append_stmt(ptr_load);
            new_call.args[arg_i] = ptr_index.use_index();
        } else {
            new_call.args[arg_i] = prev_target_index.use_index();
        }
        program.append_stmt(new_call);
        Ok(())
    }

    fn append_new_target_with_context(
        &mut self,
        program: &mut FuzzProgram,
        depth: usize,
        f_name: &str,
    ) -> eyre::Result<()> {
        crate::log!(trace, "append new target : {f_name} with context");
        let mut new_call = CallStmt::generate_new(program, CallStmt::TARGET, f_name, depth + 1)?;
        program.set_calls_track_cov(false);
        new_call.track_cov = true;
        self.track_cov = false;
        let common_arg = new_call.has_overlop_arg(program, self);
        if filter_forbidden_context(f_name, self.fg.f_name, common_arg) {
            return Ok(());
        }
        if let Some(arg_pos) = common_arg {
            // use its related args as possile
            let _ = new_call.set_related_args(arg_pos, program, self, false)?;
            self.ident = CallStmt::RELATIVE.to_string();
        } else {
            let prev_target_index = program.get_stub_stmt_index().unwrap();
            new_call.contexts.push(prev_target_index);
            self.ident = CallStmt::IMPLICIT.to_string();
        }
        let _call_i = program.append_stmt(new_call);
        Ok(())
    }

    /// Insert implicit function call before this call
    fn insert_implicit_call_before(
        &mut self,
        program: &mut FuzzProgram,
        depth: usize,
    ) -> eyre::Result<MutateOperator> {
        if !crate::config::ENABLE_INTER_API_LEARN && program.parent.is_some() {
            return Ok(MutateOperator::nop());
        }
        if crate::filter_init_func(self.fg.f_name) {
            return Ok(MutateOperator::nop());
        }
        crate::log!(trace, "try find implicit context..");
        let mut use_f_name = None;
        // add optional implict context constraint
        if rng::coin() {
            filter_function_constraint_with(&self.name, |fc| {
                if let Some(ctx) = rng::choose_iter(fc.contexts.iter().filter(|ctx| {
                    ctx.related_arg_pos.is_none()
                        && ctx.is_preferred()
                        && !self.has_implicit_context(program, &ctx.f_name)
                })) {
                    crate::log!(trace, "add optioanl implicit context: {}", ctx.f_name);
                    use_f_name = Some(ctx.f_name.clone());
                }
                true
            });
        }
        let f_name = if let Some(f_name) = &use_f_name {
            f_name
        } else if let Some(f_name) = rng::choose_iter(
            global_gadgets::get_instance()
                .functions
                .keys()
                .filter(|f_name| {
                    filter_function(f_name)
                        && !self.has_implicit_context(program, f_name)
                        && !filter_forbidden_context(self.fg.f_name, f_name, None)
                }),
        ) {
            f_name
        } else {
            return Ok(MutateOperator::nop());
        };
        let rng_state = rng::save_rng_state();
        self.insert_implicit_call_with(program, f_name, depth)?;
        Ok(MutateOperator::stmt_op(
            MutateOperation::CallImplicitInsert {
                f_name: f_name.to_string(),
                rng_state,
            },
        ))
    }

    /// Insert implicit call with specific function
    fn insert_implicit_call_with(
        &mut self,
        program: &mut FuzzProgram,
        f_name: &str,
        depth: usize,
    ) -> eyre::Result<()> {
        // Implicit calls don't use other statements as arguments,
        // so it can't mutate this call's arguments.
        let _tmp = flag::ReuseStmtGuard::temp_disable();
        let new_call = CallStmt::generate_new(program, CallStmt::IMPLICIT, f_name, depth + 1)?;
        crate::log!(trace, "insert implicit call: {}", &new_call.name);
        let stmt = program.insert_or_append_stmt(new_call)?;
        self.contexts.push(stmt);
        // only this call can be track
        program.set_calls_track_cov(false);
        self.track_cov = true;
        Ok(())
    }

    /// Insert relative call before this pointer,
    /// the inserted call is related to at least one of this call's argument.
    ///
    /// the call should
    /// 1. avoid oveflapping arguments
    /// 2. avoid remove/delete existing arguments
    fn insert_relative_call_before(
        &mut self,
        program: &mut FuzzProgram,
        depth: usize,
    ) -> eyre::Result<MutateOperator> {
        if !crate::config::ENABLE_INTER_API_LEARN && program.parent.is_some() {
            return Ok(MutateOperator::nop());
        }
        // do not add relative call to init function
        if crate::filter_init_func(self.fg.f_name) {
            return Ok(MutateOperator::nop());
        }
        let mut arg_indices: Vec<usize> = (0..self.args.len()).collect();
        // make the order randomly
        rng::shuffle(&mut arg_indices);
        for arg_pos in arg_indices {
            let op = self.insert_relative_call_for_ith_arg(program, arg_pos, depth, false)?;
            if !op.is_nop() {
                return Ok(op);
            }
        }
        Ok(MutateOperator::nop())
    }

    /// Insert relative function call for i-th argument
    fn insert_relative_call_for_ith_arg(
        &mut self,
        program: &mut FuzzProgram,
        arg_pos: usize,
        depth: usize,
        init_opaque: bool,
    ) -> eyre::Result<MutateOperator> {
        crate::log!(trace, "try find relative for arg-{arg_pos}");
        // Do not consider primitive types that has contraints.
        if utils::is_primitive_type(self.fg.arg_types[arg_pos])
            && filter_function_constraint_with(&self.name, |fc| {
                fc.get_related_args(arg_pos).len() > 1
                    || !fc.arg_constraints[arg_pos].list.is_empty()
            })
        {
            return Ok(MutateOperator::nop());
        }
        let rng_state = rng::save_rng_state();
        let mut relative_f = None;
        // add optional context
        if !init_opaque && rng::coin() {
            let mut use_ctx = None;
            filter_function_constraint_with(&self.name, |fc| {
                let optioanl_ctxs = fc.contexts.iter().filter(|ctx| {
                    ctx.is_preferred()
                        && ctx.related_arg_pos == Some(arg_pos)
                        && !self.has_relative_context(program, &ctx.f_name)
                });
                use_ctx = rng::choose_iter(optioanl_ctxs).cloned();
                true
            });
            if let Some(ctx) = use_ctx {
                crate::log!(trace, "use optional realtive ctx: {ctx:?}");
                let fg = global_gadgets::get_instance().get_func_gadget(&ctx.f_name)?;
                if let Some(related_arg_pos) = check_relative_argument(&self.fg, fg, arg_pos, false)
                {
                    relative_f = Some((fg, related_arg_pos));
                }
            }
        }
        if relative_f.is_none() {
            // Find function that related to `index`
            let funcs =
                global_gadgets::get_instance()
                    .functions
                    .iter()
                    .filter_map(|(f_name, fg)| {
                        if f_name == &self.name
                            || crate::filter_function_constraint_with(f_name, |fc| {
                                fc.role.free_arg || !fc.is_success() || (init_opaque && !fc.role.init_arg)
                            })
                            || Self::has_relative_context_for_stmt(
                                program,
                                f_name,
                                &self.args[arg_pos],
                            )
                        {
                            return None;
                        }
                        if let Some(i) = check_relative_argument(&self.fg, fg, arg_pos, init_opaque)
                        {
                            // crate::log!(trace, "add {} as candidate", fg.f_name);
                            return Some((fg, i));
                        }
                        None
                    });
            relative_f = rng::choose_iter(funcs);
        }

        // Generate call and set arguments
        if let Some((fg, related_arg_pos)) = relative_f {
            if self.insert_relative_call_for_ith_arg_with(
                program,
                arg_pos,
                depth,
                init_opaque,
                fg,
                related_arg_pos,
            )? {
                return Ok(MutateOperator::stmt_op(
                    MutateOperation::CallRelatedInsert {
                        f_name: fg.f_name.to_string(),
                        arg_pos,
                        rng_state,
                    },
                ));
            }
        }
        Ok(MutateOperator::nop())
    }

    fn insert_relative_call_for_ith_arg_with(
        &mut self,
        program: &mut FuzzProgram,
        arg_pos: usize,
        depth: usize,
        init_opaque: bool,
        fg: &FnGadget,
        related_arg_pos: usize,
    ) -> eyre::Result<bool> {
        let f_name = fg.f_name;
        crate::log!(
            trace,
            "insert relative call {f_name} with argument: {related_arg_pos}"
        );
        // don't reuse arguments except `index` and its related ones
        let _tmp = flag::ReuseStmtGuard::temp_disable();
        let mut new_call = CallStmt::generate_new(program, CallStmt::RELATIVE, f_name, depth + 1)?;
        // disable this call's cov
        new_call.track_cov = false;

        // new call must use arg: load_value
        let load_value = &self.args[arg_pos];
        if !new_call.args.contains(load_value) {
            new_call.set_ith_arg_for_relative_call(
                program,
                related_arg_pos,
                load_value.use_index(),
                self.fg.arg_types[arg_pos],
            )?;
        }
        // and its related args as possile
        if !self.set_related_args(arg_pos, program, &mut new_call, init_opaque)? {
            return Ok(false);
        }

        new_call.add_required_contexts(program, depth)?;
        let call_stmt = program.insert_or_append_stmt(new_call)?;
        if init_opaque {
            let _ = program.insert_or_append_stmt(AssertStmt::assert_initialized(
                load_value.use_index(),
                call_stmt,
            ));
        }
        crate::log!(
            trace,
            "insert relative call `{f_name}` for arg-{related_arg_pos}"
        );
        Ok(true)
    }

    /// Set related args as possiple
    fn set_related_args(
        &self,
        arg_pos: usize,
        program: &mut FuzzProgram,
        new_call: &mut CallStmt,
        init_opaque: bool,
    ) -> eyre::Result<bool> {
        let related =
            inspect_function_constraint_with(&self.name, |fc| Ok(fc.get_related_args(arg_pos)))?;
        crate::log!(trace, "related args: {:?}", related);
        for r_i in related {
            if r_i == arg_pos || init_opaque && r_i > arg_pos {
                continue;
            }
            let r_value = self.args[r_i].use_index();
            if !new_call.args.contains(&r_value) {
                if let Some(i) = check_relative_argument(&self.fg, &new_call.fg, r_i, init_opaque) {
                    new_call.set_ith_arg_for_relative_call(
                        program,
                        i,
                        r_value,
                        self.fg.arg_types[r_i],
                    )?;
                } else {
                    // fail to find corresponding related arguments,
                    // so we do not push the call to context,
                    // it will be clean by check ref-use step.
                    flag::set_incomplete_gen(true);
                    crate::log!(trace, "fail to find correspoing related arguments");
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Set argument for relative call
    pub fn set_ith_arg_for_relative_call(
        &mut self,
        program: &mut FuzzProgram,
        arg_pos: usize,
        load_value: StmtIndex,
        load_type: &str,
    ) -> eyre::Result<bool> {
        let f_arg_type = self.fg.arg_types[arg_pos];
        if utils::is_same_type(load_type, f_arg_type) {
            self.args[arg_pos] = load_value;
            return Ok(false);
        } else if utils::get_pointer_inner(f_arg_type)
            .map_or(false, |inner_ty| inner_ty == load_type)
        {
            let f_ident = self.fg.arg_idents[arg_pos];
            let mut load_ptr = LoadStmt::generate_constant(f_arg_type, f_ident)?;
            let ps = load_ptr.state.get_pointer_mut()?;
            ps.pointer_location = Location::stmt(load_value.use_index());
            let ptr_stmt = program.insert_or_append_stmt(load_ptr)?;
            self.args[arg_pos] = ptr_stmt;
            return Ok(true);
        }
        eyre::bail!("type error for argument assign: {load_type} and {f_arg_type}");
    }
}

/// Check if a function has arguments that the same as `arg`
fn check_relative_argument(
    fg1: &FnGadget,
    fg2: &FnGadget,
    arg_pos: usize,
    init_opaque: bool,
) -> Option<usize> {
    let arg_ident = fg1.arg_idents[arg_pos];
    let arg_type = fg1.arg_types[arg_pos];
    let alias_arg_type = fg1.alias_arg_types[arg_pos];
    if !filter_function(fg2.f_name)
        || filter_forbidden_context(fg1.f_name, fg2.f_name, Some(arg_pos))
    {
        return None;
    }
    // do not reused arg with file constraints
    if filter_function_constraint_with(fg1.f_name, |fc| fc.is_file(arg_pos)) {
        return None;
    }
    let is_void_ptr = utils::is_void_pointer(arg_type);
    // stupid case: alias void type to another type named void
    if is_void_ptr && (alias_arg_type.contains("void") || alias_arg_type.contains("Void")) {
        return None;
    }
    // find related arg_pos in fg2
    for arg_pos2 in 0..fg2.arg_idents.len() {
        let f_arg_type = fg2.arg_types[arg_pos2];
        if utils::is_pointer_type(f_arg_type) {
            let f_ident = fg2.arg_idents[arg_pos2];
            // avoid primitive type that has different ident
            // exclude `arg*` idents since they are default ident names.
            if utils::is_primitive_type(arg_type)
                && (!f_ident.contains(arg_ident) || f_ident.starts_with("arg"))
            {
                continue;
            }
            // utils::is_primitive_pointer(arg_type)
            if filter_function_constraint_with(fg2.f_name, |fc| fc.is_file(arg_pos2)) {
                continue;
            }

            // if any of the argument has the same type with pointer,
            // or the function has one argument that its type is the pointer of argument's type.

            // check type_name if it is not void pointer
            let f_arg_type = fg2.arg_types[arg_pos2];
            if !is_void_ptr {
                if (!init_opaque && arg_type == f_arg_type)
                    || utils::const_pointer_type(arg_type) == f_arg_type
                    || utils::mut_pointer_type(arg_type) == f_arg_type
                {
                    // crate::log!(trace, "relative type match: {arg_type} vs {f_arg_type}");
                    return Some(arg_pos2);
                }
            } else {
                // We check alias type instead of cast type (`arg_type`) since it is more accurate.
                let f_alias_arg_type = fg2.alias_arg_types[arg_pos2];
                // crate::log!(trace, "check relative type : {alias_arg_type} vs. {f_alias_arg_type}");
                if (!init_opaque && alias_arg_type == f_alias_arg_type)
                    || utils::const_pointer_type(alias_arg_type) == f_alias_arg_type
                    || utils::mut_pointer_type(alias_arg_type) == f_alias_arg_type
                {
                    // crate::log!(trace, "relative type match: {alias_arg_type} vs {f_alias_arg_type}");
                    return Some(arg_pos2);
                }
            }
        }
    }
    None
}

/// Choose any existing stetements that return objects with specific type
fn find_stmts_with_type(
    program: &FuzzProgram,
    ident: &str,
    type_name: &str,
    used_args: &[StmtIndex],
) -> Option<StmtIndex> {
    // only support pointer type
    let (mut_ptr, const_ptr) = if let Some(inner) = utils::get_pointer_inner(type_name) {
        (
            utils::mut_pointer_type(inner),
            utils::const_pointer_type(inner),
        )
    } else {
        return None;
    };
    let mut after_stub = false;
    let iter = program.stmts.iter().filter_map(|indexed_stmt| {
        if indexed_stmt.stmt.is_stub() {
            after_stub = true;
        }
        if after_stub || indexed_stmt.freed.is_some() || used_args.contains(&indexed_stmt.index) {
            return None;
        }
        if let FuzzStmt::Load(load) = &indexed_stmt.stmt {
            // only consider load value is pointer here
            if !load.point_to_freed_resource(program)
                && ident == load.get_ident()
                && (load.value.type_name() == mut_ptr || load.value.type_name() == const_ptr)
            {
                return Some(indexed_stmt.index.use_index());
            }
        }
        None
    });
    rng::choose_iter(iter)
}

#[test]
fn test_add_relative_call() {
    let f_name = "test_arr";
    CONSTRAINTS.with(|c| {
        c.borrow_mut().init_func_constraint(f_name).unwrap();
        println!("constraint: {:?}", c.borrow());
    });
    flag::set_pilot_det(true);
    let mut program = FuzzProgram::generate_program_for_func(f_name).unwrap();
    println!("program: {}", program.serialize_all().unwrap());
    flag::set_pilot_det(false);
    flag::set_reuse_stmt(true);
    flag::set_single_call(false);
    let call_index = program.stmts[program.get_target_index().unwrap()]
        .index
        .use_index();
    let rela_f_name = "test_mutate_arr";
    CONSTRAINTS.with(|c| {
        c.borrow_mut().init_func_constraint(rela_f_name).unwrap();
    });
    let op = MutateOperator::new(
        Location::stmt(call_index),
        MutateOperation::CallRelatedInsert {
            f_name: rela_f_name.to_string(),
            arg_pos: 0,
            rng_state: rng::gen_rng_state(),
        },
    );
    program.mutate_program_by_op(&op).unwrap();
    println!("program: {}", program.serialize_all().unwrap());
    // test_arr's arguments used more than twice (used by test_mutate_arr)
    assert_eq!(program.stmts[1].index.get_ref_used(), 3);
    assert_eq!(program.stmts[2].index.get_ref_used(), 3);
}
