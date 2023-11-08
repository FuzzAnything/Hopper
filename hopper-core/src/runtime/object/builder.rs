//! FuzzObjectBuilder is used to generate objects at runtime by theit types,
//! The builds will be stored at global gadgets for usage at anywhere.

use std::{marker::PhantomData, collections::HashMap};

use crate::{fuzz::*, runtime::*};

/// Hold the type of objects
pub struct FuzzTypeHolder<T: ObjFuzzable + ObjGenerate + ObjectDeserialize>(PhantomData<T>);

/// Use for build new objects by its type, it is a wrapper of holder
pub type FuzzObjectBuilder = Box<dyn DynBuildFuzzObject>;

unsafe impl<T: ObjFuzzable + ObjGenerate + ObjectDeserialize> Sync for FuzzTypeHolder<T> {}
unsafe impl<T: ObjFuzzable + ObjGenerate + ObjectDeserialize> Send for FuzzTypeHolder<T> {}

/// Trait for build new objects by its type at runtime
pub trait DynBuildFuzzObject: Sync + Send {
    /// Desrialize the value the trait hold
    fn deserialize(&self, de: &mut Deserializer, state: &mut ObjectState) -> eyre::Result<FuzzObject>;
    /// Desrialize a vector of the value that the trait hold
    fn deserialize_vec(&self, de: &mut Deserializer, state: &mut ObjectState)
        -> eyre::Result<FuzzObject>;
    /// Generate the value the trait hold
    fn generate_new(&self,  state: &mut ObjectState) -> eyre::Result<FuzzObject>;
    /// Generate a vector of the value that the trait hold
    fn generate_vec(&self,  state: &mut ObjectState) -> eyre::Result<FuzzObject>;
    /// Get size of Object
    fn mem_size(&self) -> usize;
    /// Is opaque
    fn is_opaque(&self) -> bool;
    /// fields ty
    fn get_fields_ty(&self) -> HashMap<String, String>;
}

impl<T: ObjFuzzable + ObjGenerate + ObjectDeserialize> FuzzTypeHolder<T> {
    pub fn builder() -> FuzzObjectBuilder {
        Box::new(Self(PhantomData))
    }
    pub fn as_builder(self) -> FuzzObjectBuilder {
        Box::new(self)
    }
}

impl<T: ObjFuzzable + ObjGenerate + ObjectDeserialize> DynBuildFuzzObject for FuzzTypeHolder<T> {
    fn deserialize(&self, de: &mut Deserializer, state: &mut ObjectState) -> eyre::Result<FuzzObject> {
        let val = T::deserialize_obj(de, state)?;
        Ok(Box::new(val))
    }
    fn deserialize_vec(
        &self,
        de: &mut Deserializer,
        state: &mut ObjectState,
    ) -> eyre::Result<FuzzObject> {
        if de.canary {
            Ok(Box::new(CanarySlice::<T>::deserialize_obj(de, state)?))
        } else {
            Ok(Box::new(Vec::<T>::deserialize_obj(de, state)?))
        }
    }

    fn generate_new(&self,  state: &mut ObjectState) -> eyre::Result<FuzzObject> {
        Ok(Box::new(T::generate_new( state)?))
    }
    fn generate_vec(&self,  state: &mut ObjectState) -> eyre::Result<FuzzObject> {
        Ok(Box::new(Vec::<T>::generate_new( state)?))
    }
    fn mem_size(&self) -> usize {
        std::mem::size_of::<T>()
    }
    fn is_opaque(&self) -> bool {
        T::is_opaque()
    }
    fn get_fields_ty(&self) -> HashMap<String, String> {
        T::get_fields_ty()
    }
}
