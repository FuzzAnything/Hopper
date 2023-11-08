//! Describe option type's fuzzing trait
//!
//! If T is an FFI-safe non-nullable pointer type, Option<T> is guaranteed to have the same layout
//! and ABI as T and is therefore also FFI-safe. As of this writing, this covers &, &mut, and
//! function pointers, all of which can never be null.
//!
//! In FFI, Option is warpped with function pointer to bring `NULL` pointer in rust.
//!

use eyre::Context;

use crate::{config, ObjGenerate};

use super::*;

impl<T: ObjFuzzable + ObjGenerate> ObjFuzzable for Option<T> {}

impl<T: ObjValue> ObjValue for Option<T> {}

impl<T: ObjType> ObjType for Option<T> {}

impl<T: ObjectSerialize> ObjectSerialize for Option<T> {
    fn serialize_obj(&self, state: &ObjectState) -> eyre::Result<String> {
        if let Some(v) = self {
            let sub_state = state
                .last_child()
                .with_context(|| format!("failed state: {state:?}"))?;
            if sub_state.pointer.is_some() {
                let s = v.serialize_obj(sub_state)?;
                return Ok(format!("option {s}"));
            }
        }
        // avoid data is "None"
        Ok("option_ None".to_string())
    }
}

impl<T: ObjectTranslate> ObjectTranslate for Option<T> {
    fn translate_obj_to_c(
        &self,
        state: &ObjectState,
        program: &FuzzProgram,
    ) -> eyre::Result<String> {
        if let Some(v) = self {
            let s = v.translate_obj_to_c(state.last_child()?, program)?;
            Ok(s)
        } else {
            Ok("NULL".to_string())
        }
    }
}

impl<T: Serialize> Serialize for Option<T> {
    fn serialize(&self) -> eyre::Result<String> {
        if let Some(v) = self {
            let s = v.serialize()?;
            Ok(format!("option {s}"))
        } else {
            // avoid data is "None"
            Ok("option_ None".to_string())
        }
    }
}

impl<T: ObjectDeserialize + Clone> ObjectDeserialize for Option<T> {
    fn deserialize_obj(de: &mut Deserializer, state: &mut ObjectState) -> eyre::Result<Self> {
        if !config::ENABLE_SET_FN_POINTER {
            let _ = state.replace_weight(0);
        }
        state.done_deterministic();
        let sub_state = state
            .add_child(FieldKey::Option, std::any::type_name::<Option<T>>())
            .last_child_mut()?;
        if de.strip_token("option_ None") {
            return Ok(None);
        }
        de.eat_token("option")?;
        let ret = T::deserialize_obj(de, sub_state);
        match ret {
            Ok(obj) => Ok(Some(obj)),
            Err(err) => {
                if let Some(HopperError::NullFuncionPointer) = err.downcast_ref::<HopperError>() {
                    return Ok(None);
                }
                Err(err)
            }
        }
    }
}

impl<T: Deserialize> Deserialize for Option<T> {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        if de.strip_token("option_ None") {
            return Ok(None);
        }
        de.eat_token("option")?;
        let ret = T::deserialize(de)?;
        Ok(Some(ret))
    }
}
