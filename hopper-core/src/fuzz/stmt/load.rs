//! Mutate Load statement

use super::*;

impl WeightedItem for LoadStmt {
    fn get_weight(&self) -> usize {
        self.state.mutate.borrow().get_weight()
    }
}

impl StmtMutate for LoadStmt {
    fn is_deterministic(&self) -> bool {
        self.state.is_deterministic()
    }

    fn is_incompatible(&self, op: &MutateOperator) -> bool {
        matches!(
            op.op,
            MutateOperation::PointerTodo
                | MutateOperation::PointerNull
                | MutateOperation::PointerGen { rng_state: _ }
                | MutateOperation::PointerUse { loc: _ }
                | MutateOperation::PointerRet {
                    f_name: _,
                    rng_state: _
                }
                | MutateOperation::UnionNew { rng_state: _ }
        )
    }

    fn mutate(&mut self, program: &mut FuzzProgram) -> eyre::Result<MutateOperator> {
        let mut op = self.value.mutate(&mut self.state)?;
        if !program.ops.is_empty() && self.is_incompatible(&op) {
            if op.op.is_pointer_todo() {
                return Ok(MutateOperator::nop());
            }
            return Ok(op);
        }
        if op.op.is_pointer_todo() {
            op.op = pointer::mutate_pointer_location(
                program,
                &mut self.state,
                op.key.fields.as_slice(),
            )?;
        }
        Ok(op)
    }

    fn det_mutate(&mut self, _program: &mut FuzzProgram) -> eyre::Result<MutateOperator> {
        // crate::log!(trace, "det mutate: {:?}", self.value);
        self.value.det_mutate(&mut self.state)
    }

    fn mutate_by_op(
        &mut self,
        program: &mut FuzzProgram,
        keys: &[FieldKey],
        op: &MutateOperation,
    ) -> eyre::Result<()> {
        if op.is_nop() {
            return Ok(());
        }
        flag::set_mutate_ptr(false);
        let state = &mut self.state;
        let keys = crate::check_fields(keys, state);
        self.value.mutate_by_op(state, keys, op)?;
        if flag::is_mutate_ptr() {
            pointer::mutate_pointer_location_by_op(program, state, keys, op)?;
        }
        Ok(())
    }
}

impl LoadStmt {
    /// Generate variable for specific type
    pub fn generate_new(
        program: &mut FuzzProgram,
        type_name: &str,
        ident: &str,
        depth: usize,
    ) -> eyre::Result<LoadStmt> {
        let mut state = LoadStmt::new_state(ident, type_name);
        let value = global_gadgets::get_instance()
            .get_object_builder(type_name)?
            .generate_new(&mut state)?;
        pointer::generate_pointer_location(program, &mut state, depth)?;
        let load = LoadStmt::new(value, state);
        Ok(load)
    }

    /// Generate vector statement for specific type
    pub fn generate_vec(
        program: &mut FuzzProgram,
        type_name: &str,
        ident: &str,
        depth: usize,
    ) -> eyre::Result<LoadStmt> {
        let mut state =
            LoadStmt::new_state(ident, format!("alloc::vec::Vec<{type_name}>").as_str());
        let value = global_gadgets::get_instance()
            .get_object_builder(type_name)?
            .generate_vec(&mut state)?;
        pointer::generate_pointer_location(program, &mut state, depth)?;
        let load = LoadStmt::new(value, state);
        Ok(load)
    }

    /// Generate load statement without filling pointer
    fn generate_new_without_filling_pointer(type_name: &str, ident: &str) -> eyre::Result<LoadStmt> {
        let mut state = LoadStmt::new_state(ident, type_name);
        let value = global_gadgets::get_instance()
            .get_object_builder(type_name)?
            .generate_new(&mut state)?;
        let load = LoadStmt::new(value, state);
        Ok(load)
    }

    /// Generate fixed load statement, and the pointers are  null in default.
    pub fn generate_constant(type_name: &str, ident: &str) -> eyre::Result<LoadStmt> {
        let mut load_stmt = Self::generate_new_without_filling_pointer(type_name, ident)?;
        load_stmt.is_const = true;
        load_stmt.state.replace_weight(0);
        Ok(load_stmt)
    }
}
