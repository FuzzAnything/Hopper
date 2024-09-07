//! Traits for object we are fuzzing

mod builder;
pub mod canary;
pub mod fn_pointer;
mod layout;
mod number;
mod option;
mod pointer;
pub mod seq;
mod state;
mod void;
mod bitfield;

pub use builder::*;
pub use canary::*;
pub use layout::*;
pub use state::*;
pub use void::*;
pub use bitfield::*;

use downcast_rs::Downcast;
use dyn_clone::DynClone;
use std::{fmt::Debug, collections::HashMap};

use crate::{runtime::*, HopperError, ObjMutate};

pub type FuzzObject = Box<dyn ObjFuzzable>;

/// Trait for fuzzing objects
pub trait ObjFuzzable:
    ObjMutate
    + ObjValue
    + ObjectSerialize
    + Serialize
    + ObjectTranslate
    + Debug
    + Send
    + DynClone
    + Downcast
{
}

/// Trait for get object's value information
pub trait ObjValue: 'static + std::any::Any {
    /// Get type name of object
    fn type_name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }
    /// Get layout of the object
    fn get_layout(&self, _fold_ptr: bool) -> ObjectLayout {
        ObjectLayout::root(
            std::any::type_name::<Self>(),
            self as *const Self as *mut u8,
        )
    }
    // get raw pointer by key for mutating or fill pointer
    fn get_ptr_by_keys(&self, keys: &[FieldKey]) -> eyre::Result<*mut u8> {
        if !keys.is_empty() {
            unimplemented!()
        }
        Ok(self as *const Self as *mut u8)
    }
    // Is it zero or not
    fn is_zero(&self) -> bool {
        false
    }
    // get length
    fn get_length(&self) -> usize {
        1
    }
}

/// Trait for get type information
pub trait ObjType {
    /// If this type is void or not
    fn is_void() -> bool {
        false
    }
    /// If this type is primitive type or not
    fn is_primitive() -> bool {
        false
    }
    /// If it is opaque type
    /// e.g zero-size array, or type contains fields starts with '_'
    fn is_opaque() -> bool {
        false
    }

    /// add fields's types to gadgets
    fn add_fields_to_gadgets(_gadgets: &mut ProgramGadgets) {}

    /// try renew a object from antoher
    fn cast_from(_other: &FuzzObject) -> Box<Self> {
        unreachable!("the type is not support cast");
    }

    /// Get all fields
    fn get_fields_ty() -> HashMap<String, String> {
        HashMap::default()
    }
}

#[macro_export]
macro_rules! impl_obj_fuzz {
    ( $($name:ident),* ) => {
        $(
            impl ObjFuzzable for $name {}
        )*
    }
}

dyn_clone::clone_trait_object!(ObjFuzzable);
downcast_rs::impl_downcast!(ObjFuzzable);

#[test]
fn test_get_ptr() {
    let ptr = crate::test::create_test_ptr();
    let keys = [FieldKey::Pointer, FieldKey::Field("p".to_string())];
    let ptr = ptr.get_ptr_by_keys(&keys[..]).unwrap();
    println!("ptr: {ptr:?}");
}

#[test]
fn test_get_layout() {
    let val: i32 = 1;
    let layout = val.get_layout(false);
    println!("layout: {layout:?}");
    assert_eq!(layout.get_ir_fields().len(), 0);
}
