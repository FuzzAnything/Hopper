//! Describe function pointer 's fuzzing trait
//! function pointer are : Option<fn(xx) -> xx>
//!
//! ATTN: we can only choose function from gadgets,
//! and can't crate functions for pointer dynamicly.

use eyre::ContextCompat;

use super::*;

impl<T: FnFuzzable + Debug + Clone + FnSignature> ObjFuzzable for T {}

/// Type Cast FnFuzzAble to its original type
pub fn cast_fn_pointer<T: FnFuzzable + Clone>(
    f_name: &'static str,
    f: &'static dyn FnFuzzable,
    state: &mut ObjectState,
) -> eyre::Result<T> {
    // crate::log!(trace, "use {f_name} as function pointer");
    state.pointer = Some(PointerState::new_fn_pointer(f_name, false));
    state.done_deterministic();
    let f = f
        .downcast_ref::<T>()
        .context("fail to cast function pointer")?;
    Ok(f.clone())
}

pub fn cast_canary_fn_pointer<T: FnSignature>(state: &mut ObjectState) -> T {
    // crate::log!(trace, "use canary as function pointer");
    state.pointer = Some(PointerState::new_fn_pointer("__hopper_fn_canary", false));
    state.done_deterministic();
    T::canary_fn_pointer()
}

impl<T: FnFuzzable + FnSignature> ObjValue for T {}
impl<T: FnFuzzable + FnSignature> ObjType for T {}

impl<T: FnFuzzable> ObjectSerialize for T {
    fn serialize_obj(&self, state: &ObjectState) -> eyre::Result<String> {
        let fn_name = &state
            .pointer
            .as_ref()
            .context("pointer state does not exists in fn pointer!")?
            .pointer_type;
        Ok(format!("fn* {fn_name}&"))
    }
}

impl<T: FnFuzzable> ObjectTranslate for T {
    fn translate_obj_to_c(
        &self,
        state: &ObjectState,
        _program: &FuzzProgram,
    ) -> eyre::Result<String> {
        let fn_name = &state
            .pointer
            .as_ref()
            .context("pointer state does not exists in fn pointer!")?
            .pointer_type;
        Ok(format!("&{fn_name}"))
    }
}

impl<T: FnFuzzable> Serialize for T {
    fn serialize(&self) -> eyre::Result<String> {
        // we simply return null here
        Ok(format!("fn* {}&", "__null_fp"))
    }
}

impl<T: FnFuzzable + FnSignature + Clone> ObjectDeserialize for T {
    fn deserialize_obj(de: &mut Deserializer, state: &mut ObjectState) -> eyre::Result<Self> {
        de.eat_token("fn* ")?;
        let func_name = de.next_token_until("&")?;
        if func_name == "__null_fp" {
            eyre::bail!(HopperError::NullFuncionPointer);
        }
        if func_name == "__hopper_fn_canary" {
            return Ok(cast_canary_fn_pointer(state));
        }
        let fg = global_gadgets::get_instance().get_func_gadget(func_name)?;
        cast_fn_pointer(fg.f_name, fg.f, state)
    }
}

impl<T: FnFuzzable> Deserialize for T {
    fn deserialize(_de: &mut Deserializer) -> eyre::Result<Self> {
        unimplemented!();
    }
}

#[test]
fn test_fn_pointer_serde() {
    use crate::test;
    use crate::ObjectSerialize;
    let mut de = Deserializer::new("fn* func_add&", None);
    let mut state = ObjectState::root("test", "fn(u8, u8) -> u8");
    let f = <fn(u8, u8) -> u8>::deserialize_obj(&mut de, &mut state).unwrap();
    assert_eq!(f, test::func_add as fn(u8, u8) -> u8);
    let f_name = f.serialize_obj(&state).unwrap();
    assert_eq!(f_name, "fn* func_add&");
}
