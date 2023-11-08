//! Generate and mutate void
//! void is uint,  and we do nothing

use crate::{FuzzVoid, RetVoid};

use super::*;

macro_rules! impl_void {
    ($void:ident) => {
        impl ObjGenerate for $void {
            fn generate_new( state: &mut ObjectState) -> eyre::Result<Self> {
                let _  = state.replace_weight(0);
                state.done_deterministic();
                Ok(Self::default())
            }
        }

        impl ObjMutate for $void {
            fn mutate(
                &mut self,
                state: &mut ObjectState,
            ) -> eyre::Result<MutateOperator> {
                if state.is_deterministic() {
                    state.done_deterministic();
                }
                Ok(state.as_mutate_operator(MutateOperation::Nop))
            }
            fn mutate_by_op(
                &mut self,
                _state: &mut ObjectState,
                keys: &[FieldKey],
                op: &MutateOperation,
            ) -> eyre::Result<()> {
                if !keys.is_empty() {
                    unimplemented!()
                }
                match op {
                    MutateOperation::Nop => {}
                    _ => {
                        unimplemented!();
                    }
                }
                Ok(())
            }
        }
    };
}

impl_void!(FuzzVoid);
impl_void!(RetVoid);
