use eyre::Context;

use crate::{fuzz::*, runtime::*, MutateOperator};

impl FuzzProgram {
    /// Mutate the program
    pub fn mutate_program(&mut self) -> eyre::Result<()> {
        self.save_mutate_state();
        // deterministic mutation
        let _ = self.deterministic_mutate()? || 
        // random mutation
        self.random_mutate()?;
        // refine by constraints
        self.refine_program()?;
        Ok(())
    }

    /// Mutate the program's input
    pub fn mutate_program_inputs(&mut self) -> eyre::Result<()> {
        self.save_mutate_state();
        // only mutate inputs
        self.mutate_inputs()?;
        // refine by constraints
        self.refine_program()?;
        Ok(())
    }

    /// Mutate the program by specific operator
    pub fn mutate_program_by_op(
        &mut self,
        op: &MutateOperator,
    ) -> eyre::Result<()> {
        if op.key.is_released() {
            return Ok(());
        }
        let is = self.get_mut_stmt_by_index_uniq(op.key.get_index()?);
        if is.is_none() {
            return Ok(());
        }
        let is = is.unwrap();
        let mut stmt = is.stmt.lend();
        let ret = stmt.mutate_by_op(self, op.key.fields.as_slice(), &op.op);
        if let Err(err) = ret {
            crate::log!(trace, "p: {}", self.serialize().unwrap());
            crate::log!(trace, "stmt: {}", stmt.serialize().unwrap());
            crate::log!(trace, "fail to mutate by op, op: {:?}, err: {:?}", op, err);
        }
        {
            let index = self.withdraw_stmt(stmt)?;
            let mut op = op.clone();
            op.key.set_index(index);
            self.ops.push(op);
        }
        self.check_ref_use()?;
        Ok(())
    }

    /// Mutate the program by some specific operators
    pub fn mutate_program_by_ops(
        &mut self,
        ops: &[MutateOperator],
    ) -> eyre::Result<()> {
        for op in ops {
            self.mutate_program_by_op(op)?;
        }
        Ok(())
    }

    /// Post handle after single mutating operation
    fn post_handle(&mut self, op: MutateOperator) -> eyre::Result<()> {
        crate::log!(trace, "op: {}", op);
        if !op.is_nop() {
            self.ops.push(op);
        }
        self.check_ref_use()?;
        self.ops.retain(|op| !op.key.is_released());
        Ok(())
    }

    /// Deterministic mutate
    fn deterministic_mutate(&mut self) -> eyre::Result<bool> {
        let mut nop_cnt = 0;
        while let Some(is) = self
            .stmts
            .iter_mut()
            .find(|is| is.stmt.is_deterministic())
        {
            let cur_index = is.index.get();
            crate::log!(trace, "det stage on program: {}, index: {}", self.id, cur_index);
            let mut stmt = is.stmt.lend();
            let mut op = stmt.det_mutate(self)
                .with_context(|| format!("stub: {}", stmt.serialize().unwrap()))?;
            let index = self.withdraw_stmt(stmt)?;
            op.set_index(index);
            op.det = true;
            if op.is_nop() {
                // avoid stuck in det mutation
                nop_cnt += 1;
                if nop_cnt > 25 {
                    crate::log!(warn, "stuck in deterministic mutate, program: {:?}, stmt: {cur_index}", self.id);
                    break;
                }
            } else {
                self.post_handle(op)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Random mutate
    fn random_mutate(&mut self) -> eyre::Result<bool> {
        let weight_sum = super::weight::get_weight_sum(&self.stmts);
        let ratio = 5;
        let max = 3.max(64.min(weight_sum / ratio));
        let use_stacking = rng::gen_range(1..max); 
        for _ in 0..use_stacking {
            if let Some(i) = weight::choose_weighted(&self.stmts) {
               let is = &mut self.stmts[i];
                let cur_index = is.index.get();
                crate::log!(trace, "random stage on program: {}, index: {}", self.id, cur_index);
                let mut stmt = is.stmt.lend();
                let mut op = stmt.mutate(self)
                    .with_context(|| format!("stub: {}", stmt.serialize().unwrap()))?;
                let is_incompatible = stmt.is_incompatible(&op);
                let index = self.withdraw_stmt(stmt)?;
                op.set_index(index);
                self.post_handle(op)?;
                if is_incompatible && !self.ops.is_empty() {
                    break;
                }
            }
        }
        Ok(true)
    }

    /// Only mutate inputs
    fn mutate_inputs(&mut self) -> eyre::Result<bool> {
        crate::set_input_only(true);
        let weight_sum = super::weight::get_weight_sum(&self.stmts);
        let ratio = 5;
        let max = 3.max(64.min(weight_sum / ratio));
        let use_stacking = rng::gen_range(1..max);
        for _ in 0..use_stacking {
            if let Some(i) = weight::choose_weighted(&self.stmts) {
                let is = &mut self.stmts[i];
                let cur_index = is.index.get();
                let mut stmt = is.stmt.lend();
                let mut op_holder = None;
                if matches!(stmt, FuzzStmt::Load(_)) {
                    crate::log!(
                        trace,
                        "random input stage on program: {}, index: {}",
                        self.id,
                        cur_index
                    );
                    op_holder = Some(
                        stmt.mutate(self)
                            .with_context(|| format!("stub: {}", stmt.serialize().unwrap()))?,
                    );
                }
                let index = self.withdraw_stmt(stmt)?;
                if let Some(mut op) = op_holder {
                    op.set_index(index);
                    self.post_handle(op)?;
                    if !self.ops.is_empty() {
                        break;
                    }
                }
            }
        }
        crate::set_input_only(false);
        Ok(true)
    }
}

#[test]
fn test_var_mutate() {
    fn test_type(ty: &str) {
        let mut seed = FuzzProgram::default();
        let load = LoadStmt::generate_new( &mut seed, ty, "test", 0).unwrap();
        let _index = seed.append_stmt(load);
        // make it like a seed
        seed.parent = Some(0);
        for _ in 0..200 {
            let mut p = seed.clone();
            // to make index won't be drop
            let index = p.stmts[0].index.use_index();
            p.mutate_program().unwrap();
            assert!(index.get_ref_used() > 0);
        }
    }
    test_type("u8");
    test_type("i8");
    test_type("u32");
    test_type("i32");
    test_type("u64");
    test_type("i64");
    test_type("char");
    test_type("bool");
    test_type("f32");
    test_type("f64");
    test_type("[u8; 10]");
    test_type("hopper::runtime::FuzzMutPointer<u8>");
    test_type("hopper::test::TestType");
}
