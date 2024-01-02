//! Generate and mutate option

use crate::{config, FieldKey, HopperError, ObjFuzzable};

use super::*;

/// Generate data inside option
fn generate_inner<T: ObjGenerate>(state: &mut ObjectState) -> eyre::Result<Option<T>> { 
    match T::generate_new(state) {
        Ok(obj) => Ok(Some(obj)),
        Err(err) => {
            // For fn pointer, if we can't find any valid fn, it should be NONE
            if let Some(HopperError::NullFuncionPointer) = err.downcast_ref::<HopperError>() {
                return Ok(None);
            }
            Err(err)
        }
    }
}

impl<T: ObjGenerate> ObjGenerate for Option<T> {
    fn generate_new(state: &mut ObjectState) -> eyre::Result<Self> {
        state.done_deterministic_itself();
        let sub_state = state
            .add_child(FieldKey::Option, std::any::type_name::<Option<T>>())
            .last_child_mut()?;
        if !config::ENABLE_SET_FN_POINTER {
            let _ = state.replace_weight(0);
            return Ok(None);
        }
        if rng::mostly() && !flag::is_pilot_det() {
            return Ok(None);
        }
        generate_inner(sub_state)
    }
}

impl<T: ObjGenerate + ObjFuzzable> ObjMutate for Option<T> {
    fn mutate(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        if !config::ENABLE_SET_FN_POINTER {
            return Ok(MutateOperator::nop());
        }
        let op = if let Some(val) = self {
            if rng::likely() {
                *self = None;
                state.last_child_mut()?.pointer.take();
                MutateOperation::OptionNone
            } else {
                return val.mutate(state.last_child_mut()?);
            }
        } else {
            // None
            let rng_state = rng::save_rng_state();
            *self = generate_inner(state.last_child_mut()?)?;
            MutateOperation::OptionNew { rng_state }
        };
        Ok(state.as_mutate_operator(op))
    }

    fn mutate_by_op(
        &mut self,
        state: &mut ObjectState,
        keys: &[FieldKey],
        op: &MutateOperation,
    ) -> eyre::Result<()> {
        // crate::log!(trace, "state: {:?}", state);
        match op {
            MutateOperation::PointerGen { rng_state }
            | MutateOperation::OptionNew { rng_state } => {
                let _tmp_rng = rng::TempRngGuard::temp_use(rng_state);
                *self = generate_inner(state.last_child_mut()?)?;
            }
            MutateOperation::OptionNone | MutateOperation::PointerNull => {
                if self.is_none() {
                    flag::set_refine_suc(false);
                } else {
                    *self = None;
                    state.last_child_mut()?.pointer.take();
                }
            }
            MutateOperation::FnPointer { f_name: _ } => {
                eyre::ensure!(keys[0] == FieldKey::Option, "key should be option!");
                if self.is_none() {
                    *self = generate_inner(state.last_child_mut()?)?;
                }
                if let Some(val) = self {
                    val.mutate_by_op(state.last_child_mut()?, &keys[1..], op)?;
                }
            }
            MutateOperation::PointerCanary => {
                if self.is_none() {
                    *self = generate_inner(state.last_child_mut()?)?;
                }
                if let Some(val) = self {
                    val.mutate_by_op(state.last_child_mut()?, keys, op)?;
                }
            }
            _ => {
                eyre::bail!("keys: {:?}, op: {:?}", keys, op);
            }
        }
        Ok(())
    }
}
