use super::*;
use crate::{FieldKey, ObjType, ObjectState};

/// Trait for creating new object that generate form nothing
pub trait ObjGenerate: Clone + ObjType {
    /// Generate a totally new object
    fn generate_new(state: &mut ObjectState) -> eyre::Result<Self>;
}

/// Trait for mutating object
pub trait ObjMutate {
    /// Mutate object itself
    fn mutate(
        &mut self,
        state: &mut ObjectState,
    ) -> eyre::Result<MutateOperator>;
    /// Deterministic mutate
    fn det_mutate(
        &mut self,
        state: &mut ObjectState,
    ) -> eyre::Result<MutateOperator> {
        state.done_deterministic();
        Ok(MutateOperator::nop())
    }
    /// Mutate object by operator
    fn mutate_by_op(
        &mut self,
        state: &mut ObjectState,
        keys: &[FieldKey],
        op: &MutateOperation,
    ) -> eyre::Result<()>;
}

/// Corpus of interesting values
pub trait ObjCorpus: Sized {
    /// Size of corpus
    fn corpus_size() -> usize {
        0
    }
    /// Get interesting value in corpus
    fn get_interesting_value(_index: usize) -> Option<Self> {
        None
    }
}

mod corpus;
mod fn_pointer;
mod number;
mod option;
pub mod pointer;
pub mod seq;
mod void;
pub mod buf;
mod bitfield;