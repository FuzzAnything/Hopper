//! Generate and mutatte fn pointer

use super::*;
use crate::{global_gadgets, runtime::fn_pointer::cast_fn_pointer, FnFuzzable, FnSignature, fn_pointer::cast_canary_fn_pointer};
use std::fmt::Debug;

impl<T: FnFuzzable + Debug + Clone + FnSignature> ObjGenerate for T {
    /// Choose any function from gadgets
    fn generate_new(state: &mut ObjectState) -> eyre::Result<Self> {
        let (func_name, f) = choose_function_pointer::<T>()?;
        cast_fn_pointer(func_name, f, state)
    }
}

impl<T: FnFuzzable + Debug + Clone + FnSignature> ObjMutate for T {
    /// Re-Choose any function from gadgets
    fn mutate(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        let op = if let Ok((func_name, f)) = choose_function_pointer::<T>() {
            *self = cast_fn_pointer(func_name, f, state)?;
            MutateOperation::FnPointer {
                f_name: func_name.into(),
            }
        } else {
            MutateOperation::Nop
        };
        Ok(state.as_mutate_operator(op))
    }
    fn mutate_by_op(
        &mut self,
        state: &mut ObjectState,
        keys: &[FieldKey],
        op: &MutateOperation,
    ) -> eyre::Result<()> {
        match op {
            MutateOperation::FnPointer { f_name } => {
                let fg = global_gadgets::get_instance().get_func_gadget(f_name)?;
                if T::arg_type_names() != fg.arg_types || T::ret_type_name() != fg.ret_type {
                    eyre::bail!("function pointer type mismatch");
                }
                *self = cast_fn_pointer(fg.f_name, fg.f, state)?;
            }
            MutateOperation::PointerCanary => {
                *self = cast_canary_fn_pointer(state);
            }
            _ => {
                eyre::bail!("fail to mutate pointer, keys: {keys:?}, op: {op:?}");
            }
        }
        Ok(())
    }
}

/// Random choose function from existing gadgets,
/// which should has the same signature with `T`
fn choose_function_pointer<T: FnSignature>(
) -> eyre::Result<(&'static String, &'static dyn FnFuzzable)> {
    let cands = global_gadgets::get_instance()
        .functions
        .iter()
        .filter(|(f_name, fg)| {
            crate::filter_fn_pointer(f_name)
                && T::arg_type_names() == fg.arg_types
                && T::ret_type_name() == fg.ret_type
        });
    rng::choose_iter(cands)
        .map(|(name, fg)| (name, fg.f))
        .ok_or_else(|| {
            // spefic error for telling the option warpper should be None
            crate::log!(trace, "fail to find a function pointer");
            eyre::eyre!(crate::HopperError::NullFuncionPointer)
        })
}
