use crate::{HopperBindgenBitfieldUnit, ObjFuzzable};

use super::*;

impl<Storage: ObjGenerate> ObjGenerate for HopperBindgenBitfieldUnit<Storage> {
    fn generate_new(state: &mut ObjectState) -> eyre::Result<Self> {
        let sub_state = state
            .add_child(
                FieldKey::Field("storage".to_string()),
                std::any::type_name::<Storage>(),
            )
            .last_child_mut()?;
        Ok(Self{ storage: Storage::generate_new(sub_state)? })
    }
}

impl<Storage: ObjFuzzable> ObjMutate for HopperBindgenBitfieldUnit<Storage> {
    fn mutate(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        self.storage.mutate(state.last_child_mut()?)
    }

    fn mutate_by_op(
        &mut self,
        state: &mut ObjectState,
        keys: &[FieldKey],
        op: &MutateOperation,
    ) -> eyre::Result<()> {
        self.storage.mutate_by_op(state.last_child_mut()?, keys, op)
    }
}
