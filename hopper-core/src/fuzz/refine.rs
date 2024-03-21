use std::{collections::HashMap, default};

use eyre::{Context, ContextCompat};

use crate::{fuzz::*, runtime::*, utils};

impl FuzzProgram {
    /// Refine program by constraints
    pub fn refine_program(&mut self) -> eyre::Result<Vec<MutateOperator>> {
        let mut ops = vec![];
        if !crate::config::ENABLE_REFINE {
            return Ok(ops);
        }
        crate::log!(
            trace,
            "program before refine: {}",
            self.serialize_all().unwrap()
        );
        // add required assertion before refining
        self.insert_required_assertions()?;

        // start refining
        let mut index = self
            .stmts
            .last()
            .ok_or_else(|| eyre::eyre!("has last"))?
            .index
            .use_index();
        loop {
            let cur_stmt = &self.stmts[index.get()].stmt;
            eyre::ensure!(index.get() < 4096, "index is too large");
            match cur_stmt {
                FuzzStmt::Call(call) => {
                    let call_name = call.fg.f_name;
                    let call_args = call.args.clone();
                    let existing_ctxs = call.contexts.clone();
                    // let is_context = call.is_implicit() || call.is_relative();
                    crate::log!(
                        trace,
                        "refine func constraints: {call_name} at {}",
                        index.get()
                    );
                    crate::inspect_function_constraint_with(call_name, |fc| {
                        for (arg_pos, tc) in fc.arg_constraints.iter().enumerate() {
                            if tc.list.is_empty() {
                                continue;
                            }
                            crate::log!(trace, "arg_pos: {arg_pos}");
                            let arg_stmt = &call_args[arg_pos];
                            let call_info = Some((index.get(), &call_args[..]));
                            let mut operators =
                                self.refine_type_constraints(arg_stmt, tc, None, call_info)?;
                            if !operators.is_empty() {
                                ops.append(&mut operators);
                            }
                        }
                        // refine contexts
                        for ctx_rule in &fc.contexts {
                            self.refine_contexts(&index, ctx_rule, &call_args, &existing_ctxs)?;
                        }
                        // FIXME: it's bad, which may ruin the program. Something like assert may depend on it.
                        /*
                        if fc.insert_fail && is_context {
                            crate::log!(trace, "insert {} fail and removed", call_name);
                            let cur = index.get();
                            self.delete_stmt(cur);
                            // switch to next one, since current index is deleted.
                            index = self.stmts[cur].index.use_index();
                            self.check_ref_use()?;
                        }
                        */
                        let mut operators = self.refine_length_factors(fc, &call_args)?;
                        if !operators.is_empty() {
                            ops.append(&mut operators);
                        }
                        Ok(())
                    })?;
                }
                FuzzStmt::Load(load) => {
                    let type_name = load.value.type_name();
                    if !(utils::is_primitive_type(type_name) || utils::is_option_type(type_name)) {
                        let stmt_index = index.use_index();
                        let next_index = if index.get() + 1 >= self.stmts.len() {
                            index.use_index()
                        } else {
                            self.stmts[index.get() + 1].index.use_index()
                        };
                        // refine fields in load statement with general type constraints
                        crate::iterate_type_constraint_with(|ty, tc| {
                            if let FuzzStmt::Load(load_inner) = &self.stmts[stmt_index.get()].stmt {
                                // find fields with type in load
                                let fields_list =
                                    load_inner.state.find_fields_with(|s| s.ty == ty, false);
                                for prefix in fields_list {
                                    let mut operators = self.refine_type_constraints(
                                        &stmt_index,
                                        tc,
                                        Some(prefix),
                                        None,
                                    )?;
                                    // refine new generating stmts during stmt_index..next_index
                                    if operators.iter().any(|op| {
                                        matches!(op.op, MutateOperation::InitTypeWithCall)
                                    }) {
                                        crate::log!(
                                            trace,
                                            "roll back to next index: {}",
                                            next_index.get()
                                        );
                                        // crate::log!(trace, "after init, program: {}", self.serialize().unwrap());
                                        index = next_index.use_index();
                                    }
                                    if !operators.is_empty() {
                                        ops.append(&mut operators);
                                    }
                                }
                            }
                            Ok(())
                        })?;
                    }
                }
                _ => {}
            }
            if index.get() == 0 {
                break;
            }
            if index.get() >= self.stmts.len() {
                crate::log_error!("program: {}", self);
                eyre::bail!("the index {} is out of range!", index.get());
            }
            index = self.stmts[index.get() - 1].index.use_index();
        }
        crate::log!(trace, "refine ops: {:?}", ops);

        drop(index);
        // check_ref_use again.
        self.check_ref_use()?;

        Ok(ops)
    }

    fn refine_type_constraints(
        &mut self,
        stmt_index: &StmtIndex,
        constraint: &TypeConstraint,
        prefix: Option<LocFields>,
        call_info: Option<(usize, &[StmtIndex])>,
    ) -> eyre::Result<Vec<MutateOperator>> {
        let mut operators = vec![];
        // used for refine constraint in general types
        let prefix = prefix.unwrap_or_default();
        // used for refine constraint in arguments
        let (call_i, call_args) = call_info.unwrap_or((0, &[]));
        for citem in constraint.list.iter() {
            crate::log!(trace, "stmt: {}, constraint: {:?}", stmt_index.get(), citem);
            let lcs = citem.find_all_locations_with_any_index(self, stmt_index, &prefix);
            eyre::ensure!(lcs.len() <= 10000, "fail to refine");
            for (loc, constraint) in lcs {
                crate::log!(trace, "refining loc: {}", loc.serialize().unwrap());
                let operator = match &constraint {
                    Constraint::SetNull => {
                        if self.is_loc_null(&loc) {
                            continue;
                        }
                        MutateOperator::new(loc, MutateOperation::PointerNull)
                    }
                    Constraint::NonNull => {
                        // if the pointer is null, we set it to non-null
                        if !self.is_loc_null(&loc) {
                            continue;
                        }
                        MutateOperator::new(
                            loc,
                            MutateOperation::PointerGen {
                                rng_state: rng::gen_rng_state(),
                            },
                        )
                    }
                    Constraint::SetVal { val } => {
                        if val.is_factor() {
                            crate::log!(trace, "skip factor");
                            continue;
                        }
                        let op = if let IrEntry::String(buf) = val {
                            MutateOperation::BufRefine {
                                buffer: buf.as_bytes().to_vec(),
                            }
                        } else {
                            // make sure can handle length stored in a pointer, e.g. (int* array, int* size)
                            MutateOperation::IntSet {
                                val: val.convert_length_to_constant(
                                    self, stmt_index, &prefix, call_args,
                                )?,
                            }
                        };
                        MutateOperator::new(loc, op)
                    }
                    Constraint::Range { min, max } => {
                        if max.is_factor() {
                            crate::log!(trace, "skip factor");
                            continue;
                        }
                        MutateOperator::new(
                            loc,
                            MutateOperation::IntRange {
                                min: min.convert_length_to_constant(
                                    self, stmt_index, &prefix, call_args,
                                )?,
                                max: max.convert_length_to_constant(
                                    self, stmt_index, &prefix, call_args,
                                )?,
                            },
                        )
                    }
                    Constraint::NonZero => MutateOperator::new(
                        loc,
                        MutateOperation::IntRange {
                            min: 1.into(),
                            max: IrEntry::Max(0),
                        },
                    ),
                    Constraint::CastFrom { cast_type }
                        if (self.parent.is_none() || self.is_loc_mutated(&loc))
                            && self.is_loc_null(&loc) =>
                    {
                        MutateOperator::new(
                            loc,
                            MutateOperation::PointerCast {
                                cast_type: cast_type.to_string(),
                                rng_state: rng::gen_rng_state(),
                            },
                        )
                    }
                    Constraint::UseUnionMember { member } => MutateOperator::new(
                        loc,
                        MutateOperation::UnionUse {
                            rng_state: rng::gen_rng_state(),
                            member: member.clone(),
                        },
                    ),
                    Constraint::ArrayLength { len } => {
                        // there are two cases that may be ambiguous in pointer's VecPad
                        // 1. used in custom rule without & (pointer)
                        // 2. pointer to another pointer, and the pointee is not a vector (reuse case)
                        // to support both, we make the latter to the former here
                        let mut loc = loc;
                        if citem.key.list.last() == Some(&FieldKey::Pointer) {
                            if let FuzzStmt::Load(load) = &self.stmts[loc.get_index()?.get()].stmt {
                                if !utils::is_vec_type(load.value.type_name()) {
                                    let mut new_key = citem.key.clone();
                                    new_key.list.pop();
                                    loc = new_key
                                        .to_loc_for_refining(self, stmt_index, &prefix)
                                        .context("has loc")?;
                                }
                            }
                        }
                        if let IrEntry::Constant(len) =
                            len.convert_length_to_constant(self, stmt_index, &prefix, call_args)?
                        {
                            let mut new_len = 1;
                            if len > 1 {
                                new_len = len as usize;
                            }
                            MutateOperator::new(
                                loc,
                                MutateOperation::VecPad {
                                    len: new_len,
                                    zero: false,
                                    rng_state: rng::gen_rng_state(),
                                },
                            )
                        } else {
                            continue;
                        }
                    }
                    Constraint::NeedInit => {
                        // State that does not require initialization
                        // 1. non-null opqaque pointer
                        // 2. null pointer with inialization functions
                        if !self.is_loc_null(&loc) || self.has_been_inited(stmt_index).is_some() {
                            continue;
                        }
                        MutateOperator::new(loc, MutateOperation::InitOpaque { call_i })
                    }
                    Constraint::File { read, is_fd } => {
                        if *is_fd {
                            if self.refine_fd(stmt_index, &loc, *read)? {
                                operators.push(MutateOperator::new(loc, MutateOperation::FdFile));
                            }
                            continue;
                        }
                        if self.is_file_loc(&loc) {
                            crate::log!(trace, "loc is file");
                            continue;
                        }
                        MutateOperator::new(loc, MutateOperation::PointerFile { read: *read })
                    }
                    Constraint::InitWith { f_name, arg_pos } => {
                        if let Some(op) =
                            self.init_with(f_name, *arg_pos, stmt_index, loc, &prefix)?
                        {
                            operators.push(op);
                        }
                        continue;
                    }
                    _ => {
                        continue;
                    }
                };
                if self.refine_load_statement(&operator)? {
                    operators.push(operator);
                }
            }
        }
        Ok(operators)
    }

    fn refine_load_statement(&mut self, op: &MutateOperator) -> eyre::Result<bool> {
        flag::set_refine_suc(true);
        let is = self
            .get_mut_stmt_by_index_uniq(op.key.stmt_index.as_ref().unwrap())
            .with_context(|| format!("can't find stmt with op: {op:?}"))?;
        let mut stmt = is.stmt.lend();
        if stmt.is_load() {
            stmt.mutate_by_op(self, op.key.fields.as_slice(), &op.op)
                .with_context(|| {
                    format!(
                        "op: {}, stub: {}",
                        op.serialize().unwrap(),
                        stmt.serialize().unwrap()
                    )
                })?;
        } else {
            // ignore calls
            flag::set_refine_suc(false);
        }
        let _ = self.withdraw_stmt(stmt)?;
        crate::log!(trace, "refine statement by : {}", op);
        Ok(flag::is_refine_suc())
    }

    fn refine_fd(
        &mut self,
        stmt_index: &StmtIndex,
        loc: &Location,
        read: bool,
    ) -> eyre::Result<bool> {
        crate::log!(trace, "crate a file fd for loc :{loc:?}");
        if loc.fields.is_empty() {
            if let Some(is) = self.get_mut_stmt_by_index_uniq(stmt_index) {
                // check if has refined
                if matches!(&is.stmt, FuzzStmt::File(_)) {
                    return Ok(false);
                }
                let _ = is.stmt.lend();
                let file_stmt = FileStmt::generate_new(self, "fd", false, true, read, 0)?;
                let _ = self.withdraw_stmt(file_stmt.into())?;
                return Ok(true);
            }
        } else if let Some(pos) = self.position_stmt_by_index_uniq(stmt_index) {
            // check if has refined
            if self.stmts[pos..].iter().any(|is| {
                if let FuzzStmt::Update(update_stmt) = &is.stmt {
                    if loc.compare_weak(&update_stmt.dst) {
                        if let Some(file_is) = self.get_stmt_by_index_uniq(&update_stmt.src) {
                            if matches!(&file_is.stmt, FuzzStmt::File(_)) {
                                return true;
                            }
                        }
                    }
                }
                false
            }) {
                return Ok(false);
            }
            // get next one and insert update
            if pos + 1 < self.stmts.len() {
                let next_stmt = self.stmts[pos + 1].stmt.lend();
                let file_stmt = FileStmt::generate_new(self, "fd", false, true, read, 0)?;
                let file_index = self.insert_or_append_stmt(file_stmt)?;
                let update_stmt = UpdateStmt::new(file_index, loc.to_weak_loc());
                let _ = self.insert_or_append_stmt(update_stmt)?;
                let _ = self.withdraw_stmt(next_stmt)?;
            }
        }
        Ok(false)
    }

    fn init_with(
        &mut self,
        f_name: &str,
        arg_pos: usize,
        stmt_index: &StmtIndex,
        loc: Location,
        prefix: &LocFields,
    ) -> eyre::Result<Option<MutateOperator>> {
        if !prefix.is_empty() || CallStmt::has_relative_context_for_stmt(self, f_name, stmt_index) {
            return Ok(None);
        }
        crate::log!(
            trace,
            "init with loc :{loc:?} with {f_name} at arg-{arg_pos}"
        );
        if let FuzzStmt::Load(load) = &self.stmts[stmt_index.get()].stmt {
            let type_name = load.value.type_name();
            let stub_stmt = self.stmts[stmt_index.get() + 1].stmt.lend();
            let _tmp = flag::ReuseStmtGuard::temp_disable();
            let mut rela_call = CallStmt::generate_new(self, CallStmt::RELATIVE, f_name, 0)?;
            let init_arg = rela_call.set_ith_arg_for_relative_call(
                self,
                arg_pos,
                stmt_index.use_index(),
                type_name,
            )?;
            let call_stmt = self.insert_or_append_stmt(rela_call)?;
            if init_arg {
                let _ = self.insert_or_append_stmt(AssertStmt::assert_initialized(
                    stmt_index.use_index(),
                    call_stmt,
                ));
            }
            let _ = self.withdraw_stmt(stub_stmt);
            self.check_ref_use()?;
            return Ok(Some(MutateOperator::new(
                loc,
                MutateOperation::InitTypeWithCall,
            )));
        }
        Ok(None)
    }

    fn refine_contexts(
        &mut self,
        call_index: &StmtIndex,
        ctx_rule: &CallContext,
        call_args: &[StmtIndex],
        existing_ctxs: &[StmtIndex],
    ) -> eyre::Result<()> {
        if ctx_rule.is_forbidden() {
            crate::log!(trace, "refine context: {ctx_rule:?}");
            if let Some(arg_pos) = ctx_rule.related_arg_pos {
                let arg_stmt = &call_args[arg_pos];
                for is in &self.stmts {
                    if &is.index == call_index {
                        break;
                    }
                    if let FuzzStmt::Call(call) = &is.stmt {
                        if call.fg.f_name == ctx_rule.f_name
                            && call.is_relative()
                            && call.is_related_call_for_stmt(arg_stmt, self)
                        {
                            self.delete_stmt(is.index.get());
                            self.check_ref_use()?;
                            break;
                        }
                    }
                }
            } else {
                for current_ctx in existing_ctxs {
                    if let Some(implicit_call) = self.get_call_stmt(current_ctx.get()) {
                        if implicit_call.fg.f_name == ctx_rule.f_name {
                            self.delete_stmt(current_ctx.get());
                            self.check_ref_use()?;
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn refine_length_factors(
        &mut self,
        // call_index: usize,
        //call: &CallStmt,
        fc: &FuncConstraint,
        call_args: &[StmtIndex],
    ) -> eyre::Result<Vec<MutateOperator>> {
        #[derive(Debug)]
        struct FactorItem {
            pub arg_pos: usize,
            pub fields: LocFields,
            pub range_start: Option<u64>,
        }
        #[derive(Debug)]
        struct FactorList {
            pub coef: u64,
            pub list: Vec<FactorItem>,
        }
        impl default::Default for FactorList {
            fn default() -> Self {
                Self {
                    coef: 1,
                    list: vec![],
                }
            }
        }
        let mut factors_map: HashMap<(usize, LocFields), FactorList> = HashMap::default();
        macro_rules! get_factor_list {
            ($k_arg: ident, $k_fields: expr) => {{
                factors_map
                    .entry(($k_arg, $k_fields.clone()))
                    .or_insert(FactorList::default())
            }};
        }

        for (key_arg_pos, tc) in fc.arg_constraints.iter().enumerate() {
            for c in tc.list.iter() {
                match &c.constraint {
                    Constraint::LengthFactor { coef } => {
                        let f = get_factor_list!(key_arg_pos, c.key);
                        f.coef = *coef;
                    }
                    Constraint::SetVal {
                        val:
                            IrEntry::Length {
                                arg_pos,
                                fields,
                                is_factor,
                            },
                    } => {
                        if !*is_factor {
                            continue;
                        }
                        let arg_pos = arg_pos.unwrap_or_default();
                        let f: &mut FactorList = get_factor_list!(arg_pos, fields);
                        f.list.push(FactorItem {
                            arg_pos: key_arg_pos,
                            fields: c.key.clone(),
                            range_start: None,
                        });
                    }
                    Constraint::Range {
                        min,
                        max:
                            IrEntry::Length {
                                arg_pos,
                                fields,
                                is_factor,
                            },
                    } => {
                        if !*is_factor {
                            continue;
                        }
                        let range_start = if let IrEntry::Constant(start) = min {
                            Some(*start)
                        } else {
                            None
                        };
                        let arg_pos = arg_pos.unwrap_or_default();
                        let f: &mut FactorList = get_factor_list!(arg_pos, fields);
                        f.list.push(FactorItem {
                            arg_pos: key_arg_pos,
                            fields: c.key.clone(),
                            range_start,
                        });
                    }
                    _ => {}
                }
            }
        }
        crate::log!(trace, "find factors: {factors_map:?}");
        let mut operators = vec![];
        for ((arr_arg_pos, arr_fields), factors) in factors_map {
            let arr_stmt = &call_args[arr_arg_pos];
            let Some(arr_loc) =
                arr_fields.to_loc_for_refining(self, arr_stmt, &LocFields::default())
            else {
                continue;
            };
            let stmt_i = arr_loc.stmt_index.as_ref().unwrap().get();
            if let FuzzStmt::Load(load) = &self.stmts[stmt_i].stmt {
                let state = load.state.get_child_by_fields(arr_loc.fields.as_slice())?;
                let mut len = get_ptee_vec_len(state, &self.stmts)?;
                if len == 0 {
                    for f in factors.list.iter() {
                        let cur_stmt = &call_args[f.arg_pos];
                        if let Some(num_loc) =
                            f.fields
                                .to_loc_for_refining(self, cur_stmt, &LocFields::default())
                        {
                            let set_zero = MutateOperation::IntSet { val: 0.into() };
                            let op = MutateOperator::new(num_loc, set_zero);
                            if self.refine_load_statement(&op)? {
                                operators.push(op);
                            }
                        }
                    }
                    continue;
                }
                // if len is not multiple of coef
                let rem = len % factors.coef;
                if rem > 0 {
                    let pad_len = factors.coef - rem;
                    crate::log!(
                        trace,
                        "adding {pad_len} elements, to make length to be multiple of coef"
                    );
                    // FIXME: arr_loc is wrong
                    len += pad_len;
                    let op = MutateOperator::new(
                        arr_loc,
                        MutateOperation::VecPad {
                            len: len as usize,
                            zero: false,
                            rng_state: rng::gen_rng_state(),
                        },
                    );
                    if self.refine_load_statement(&op)? {
                        operators.push(op);
                    }
                }

                // To make sure the buffer won't overflow, we do not use div_ceil here.
                // FIXME: it may brings noise for minimize (ops)
                let mut remain = len / factors.coef;
                if remain == 0 {
                    remain = 1;
                }
                let mut max = 1;
                let mut f_iter = factors.list.iter().peekable();
                while let Some(f) = f_iter.next() {
                    // is the last
                    remain /= max;
                    if f_iter.peek().is_none() {
                        max = remain
                    } else {
                        max = rng::gen_range(1..=remain);
                    }
                    crate::log!(trace, "remain: {remain}");
                    let cur_stmt = &call_args[f.arg_pos];
                    if let Some(num_loc) =
                        f.fields
                            .to_loc_for_refining(self, cur_stmt, &LocFields::default())
                    {
                        let cur_num = self.find_number_by_loc(num_loc.clone())?;
                        crate::log!(trace, "cur_num: {cur_num}");
                        let op = if let Some(start) = f.range_start {
                            if cur_num >= start && cur_num < remain {
                                crate::log!(trace, "in range, skip");
                                max = cur_num + 1;
                                continue;
                            }
                            MutateOperation::IntRange {
                                min: start.into(),
                                max: max.into(),
                            }
                        } else {
                            if cur_num > 0 && cur_num <= remain {
                                crate::log!(trace, "in range, skip");
                                max = cur_num;
                                continue;
                            }
                            MutateOperation::IntSet { val: max.into() }
                        };
                        let op = MutateOperator::new(num_loc, op);
                        if self.refine_load_statement(&op)? {
                            operators.push(op);
                        }
                    }
                }
            }
        }
        Ok(operators)
    }
}

const DEFAULT_PTR_LEN: u64 = 1;

impl IrEntry {
    fn convert_length_to_constant(
        &self,
        program: &FuzzProgram,
        stmt_index: &StmtIndex,
        prefix: &LocFields,
        call_args: &[StmtIndex],
    ) -> eyre::Result<Self> {
        if let Self::Length {
            arg_pos,
            fields,
            is_factor: _,
        } = &self
        {
            let mut stmt_index = stmt_index;
            if let Some(arg_pos) = arg_pos {
                stmt_index = &call_args[*arg_pos];
            }
            let mut val = DEFAULT_PTR_LEN;
            if let Some(loc) = fields.to_loc_for_refining(program, stmt_index, prefix) {
                let stmt_i = loc.stmt_index.unwrap().get();
                if let FuzzStmt::Load(load_tmp) = &program.stmts[stmt_i].stmt {
                    let state = load_tmp.state.get_child_by_fields(loc.fields.as_slice())?;
                    val = get_ptee_vec_len(state, &program.stmts)?;
                }
            }
            Ok(Self::Constant(val))
        } else {
            Ok(self.clone())
        }
    }
}

fn get_ptee_vec_len(ptr_state: &ObjectState, stmts: &[IndexedStmt]) -> eyre::Result<u64> {
    if let Some(ps) = &ptr_state.pointer {
        let dst_loc = &ps.pointer_location;
        if dst_loc.is_null() {
            crate::log!(trace, "ptr point to null: {:?}", dst_loc);
            return Ok(0);
        }
        let dst_stmt = dst_loc.stmt_index.as_ref().context("has index")?;
        if let FuzzStmt::Load(load_vec) = &stmts[dst_stmt.get()].stmt {
            let len = load_vec.value.get_length();
            return Ok(len as u64);
        }
        // call: 1
    }
    Ok(DEFAULT_PTR_LEN)
}

impl TypeConstraintItem {
    /// Find all posiible locations without the limiration of indices.
    /// e.g  if `self` is &.0.xx , and we find &.1 and &.2 exists, we list them.
    /// However, we only traverse the indices in one dimension.
    pub fn find_all_locations_with_any_index(
        &self,
        program: &FuzzProgram,
        stmt_index: &StmtIndex,
        prefix: &LocFields,
    ) -> Vec<(Location, Constraint)> {
        let mut locs = vec![];
        // skip factors
        let c_loc = match &self.constraint {
            Constraint::SetVal { val } => Some(val),
            Constraint::Range { min: _, max } => Some(max),
            _ => None,
        };
        if let Some(IrEntry::Length {
            arg_pos: _,
            fields: _,
            is_factor,
        }) = c_loc
        {
            if *is_factor {
                return vec![];
            }
        }
        for (i, f) in self.key.list.iter().enumerate() {
            if let FieldKey::Index(_) = f {
                let mut next_index = 0;
                loop {
                    let mut k = self.key.clone();
                    k.list[i] = FieldKey::Index(next_index);
                    crate::log!(trace, "index: {next_index}, try loc: {k:?}");
                    next_index += 1;
                    if next_index > 10000 {
                        panic!("too many indices");
                    }
                    if let Some(loc) = k.to_loc_for_refining(program, stmt_index, prefix) {
                        // update constraint, too
                        let mut c = self.constraint.clone();
                        let c_loc = match &mut c {
                            Constraint::SetVal { val } => Some(val),
                            Constraint::Range { min: _, max } => Some(max),
                            _ => None,
                        };
                        if let Some(IrEntry::Length {
                            arg_pos: _,
                            fields,
                            is_factor: _,
                        }) = c_loc
                        {
                            if fields.len() > i && &fields.list[i] == f {
                                fields.list[i] = k.list[i].clone();
                            }
                        }
                        locs.push((loc, c));
                    } else {
                        crate::log_trace!("fail to find loc");
                        break;
                    }
                }
            }
        }
        if locs.is_empty() {
            if let Some(loc) = self.key.to_loc_for_refining(program, stmt_index, prefix) {
                locs.push((loc, self.constraint.clone()));
            }
        }
        locs
    }
}

#[test]
fn test_refine_ptr_index() {
    {
        let target = "test_arr";
        CONSTRAINTS
            .with(|c| c.borrow_mut().init_func_constraint(target))
            .unwrap();
        for _ in 0..250 {
            println!("------------");
            let mut p = FuzzProgram::generate_program_for_func(target).unwrap();
            p.eval().unwrap();
        }
    }

    {
        let target = "test_index";
        let type_name = "hopper::test::TestType";
        CONSTRAINTS
            .with(|c| c.borrow_mut().init_type_constraint(type_name))
            .unwrap();
        for _ in 0..250 {
            println!("------------");
            let mut p = FuzzProgram::generate_program_for_func(target).unwrap();
            p.eval().unwrap();
        }
    }
}
