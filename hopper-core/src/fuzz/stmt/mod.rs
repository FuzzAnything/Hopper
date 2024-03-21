use crate::{impl_stmt_match, runtime::*};
use super::*;

pub trait StmtMutate: WeightedItem {
    /// Is deterministic or not
    fn is_deterministic(&self) -> bool {
        false
    }
    // Is incompatible or not
    fn is_incompatible(&self, _op: &MutateOperator) -> bool {
        false
    }
    /// Mutate the statement
    fn mutate(&mut self, _program: &mut FuzzProgram) -> eyre::Result<MutateOperator> {
        unimplemented!()
    }
    /// Det mutate
    fn det_mutate(&mut self, _program: &mut FuzzProgram) -> eyre::Result<MutateOperator> {
        unimplemented!();
    }
    /// Mutate by op
    fn mutate_by_op(
        &mut self,
        _program: &mut FuzzProgram,
        _keys: &[FieldKey],
        _op: &MutateOperation,
    ) -> eyre::Result<()> {
        unimplemented!()
    }
}

impl FuzzStmt {
    pub fn is_deterministic(&self) -> bool {
        impl_stmt_match!(self, is_deterministic)
    }
    pub fn is_incompatible(&self, op: &MutateOperator) -> bool {
        impl_stmt_match!(self, is_incompatible(op))
    }
    pub fn mutate(&mut self, program: &mut FuzzProgram) -> eyre::Result<MutateOperator> {
        impl_stmt_match!(self, mutate(program))
    }
    pub fn det_mutate(&mut self, program: &mut FuzzProgram) -> eyre::Result<MutateOperator> {
        impl_stmt_match!(self, det_mutate(program))
    }
    pub fn mutate_by_op(
        &mut self,
        program: &mut FuzzProgram,
        keys: &[FieldKey],
        op: &MutateOperation,
    ) -> eyre::Result<()> {
        impl_stmt_match!(self, mutate_by_op(program, keys, op))
    }
}

impl WeightedItem for FuzzStmt {
    fn get_weight(&self) -> usize {
        impl_stmt_match!(self, get_weight)
    }
}

impl WeightedItem for IndexedStmt {
    fn get_weight(&self) -> usize {
        self.stmt.get_weight()
    }
}

mod assert;
mod call;
mod file;
mod load;
mod update;

pub use assert::*;