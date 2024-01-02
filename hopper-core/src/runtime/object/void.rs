//! Describe void's fuzzing trait,
//! There are two kinds of void:
//! 1) RetVoid: return void, which is similar to RUST's `()`
//! 2) ArgVoid: void in arguments, or pointer, struct ..., we use cvoid directly.

use super::*;

/// Void for return
pub type RetVoid = ();

macro_rules! impl_void {
    ($void:ident) => {
        impl ObjFuzzable for $void {}

        impl ObjValue for $void {}

        impl ObjType for $void {
            fn is_void() -> bool {
                true
            }
            fn is_opaque() -> bool {
                true
            }
        }

        impl ObjectSerialize for $void {
            fn serialize_obj(&self, _state: &ObjectState) -> eyre::Result<String> {
                Ok("void".to_string())
            }
        }

        impl Serialize for $void {
            fn serialize(&self) -> eyre::Result<String> {
                Ok("void".to_string())
            }
        }

        impl ObjectTranslate for $void {}

        impl ObjectDeserialize for $void {
            fn deserialize_obj(
                de: &mut Deserializer,
                state: &mut ObjectState,
            ) -> eyre::Result<Self> {
                let _  = state.replace_weight(0);
                state.done_deterministic_itself();
                de.eat_token("void")?;
                Ok(Self::default())
            }
        }

        impl Deserialize for $void {
            fn deserialize(_de: &mut Deserializer) -> eyre::Result<Self> {
                unimplemented!();
            }
        }
    };
}

impl_void!(FuzzVoid);
impl_void!(RetVoid);

impl Clone for FuzzVoid {
    fn clone(&self) -> Self {
        // unreachable!("void can't be clone!")
        Self(0_u8)
    }
}

unsafe impl Sync for FuzzVoid {}
unsafe impl Send for FuzzVoid {}
