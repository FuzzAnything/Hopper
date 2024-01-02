//! Describe pointer's fuzzing triat
//! pointers include: *mut, *const
use super::*;
use crate::config;
use crate::ObjGenerate;

macro_rules! impl_fuzz_pointer {
    ($pointer:ident, $name:literal, $is_mut:tt) => {
        impl<T> $pointer<T> {
            pub fn new(ptr: *mut T) -> Self {
                Self(ptr)
            }

            pub fn get_inner(&self) -> *mut T {
                self.0
            }

            /// Return a pointer which points to `loc`
            pub fn loc_pointer(state: &mut ObjectState, loc: Location) -> Self {
                state.pointer = Some(PointerState::new_pointer(
                    loc,
                    std::any::type_name::<T>(),
                    $is_mut,
                ));
                state.done_deterministic_itself();
                Self(::std::ptr::null_mut())
            }

            /// Return a null pointer
            pub fn null(state: &mut ObjectState) -> Self {
                state.done_deterministic_itself();
                Self::loc_pointer(state, Location::null())
            }

            /// Return a stub pointer
            pub fn stub(state: &mut ObjectState) -> Self {
                state.done_deterministic_itself();
                let p = Self::loc_pointer(state, Location::null());
                if let Some(ps) = &mut state.pointer {
                    ps.stub = true;
                }
                p
            }

            /// Get length by memory size
            pub fn get_length_by_mem_size(size: usize) -> usize {
                let mut size = size;
                // if it malloc a huge space (may used as arena)
                if size > config::MAX_INPUT_SZIE {
                    size = config::MAX_INPUT_SZIE;
                }
                let obj_size = std::mem::size_of::<T>();
                if obj_size == 0 {
                    size = 1;
                } else if size > 1 {
                    let rem = size % obj_size;
                    size /= obj_size;
                    // the size could be not multiple of obj_size,
                    // e.g. arena, partial opaque
                    if rem > 0 {
                        size = 1;
                    }
                }
                size
            }

            /// Check if the pointed memory remains untouched since allocated or is obtained through a null pointer plus an offset.
            pub fn check_validity(&self) -> bool {
                // TODO: > 0x8000000 can only filter out the situation when a null pointer is used as the base. however, chances are that
                // a pointer with a different type is mistakenly feed in as a base pointer, and the addition of offset to the pointer makes it a
                // illegal pointer. This usually happens when an argument has the `void *` type
                (self.0 as usize) != config::UNINITIALIZED_MEMORY_MAGIC
                    && (self.0 as usize) > 0x300000
            }
        }

        unsafe impl<T> Sync for $pointer<T> {}
        unsafe impl<T> Send for $pointer<T> {}

        // Since we do not require T being Copy or Clone,
        // and we do not copy *mut T actually,
        // we implement Copy/Clone directly instead of derive..
        impl<T> Copy for $pointer<T> {}
        impl<T> Clone for $pointer<T> {
            fn clone(&self) -> Self {
                // The pointer will be updated before `eval` load statements based on their location,
                // and they will be cloned at clone arguments or fetch from returns at call statements,
                // thus we should fill old pointer here.
                // Also, we should avoid dangling pointer, so the pointers of programs in queue
                // for mutating is null due to the specifical clone `clone_without_state`.
                // Self(self.0)
                *self
            }
        }

        impl<T: ObjFuzzable> ObjFuzzable for $pointer<T> {}

        impl<T: ObjValue + Serialize + Debug> ObjValue for $pointer<T> {
            /// Get layout of the object
            fn get_layout(&self, fold_ptr: bool) -> ObjectLayout {
                let mut layout =
                    ObjectLayout::root(self.type_name(), self as *const Self as *mut u8);
                if !fold_ptr && self.check_validity() && !self.0.is_null() {
                    // If the pointer has point-to sth, we add its layout with `pointer` key.
                    // To avoid recursion, we expand layout lazily.
                    // Also, we should ensure it is not a dangling pointer.
                    // the pointer key will only exist in return value in call stmt,
                    // since it is null in load stmt.
                    let ptr = self.0;
                    let mut ptr_layout =
                        ObjectLayout::root(std::any::type_name::<T>(), ptr as *mut u8);
                    // lazy load
                    ptr_layout.set_lazy_loader(move |size: usize| {
                        if size == 0 {
                            return vec![];
                        }
                        let len = Self::get_length_by_mem_size(size);
                        let v = unsafe { std::slice::from_raw_parts(ptr as *const T, len) };
                        v.get_layout(fold_ptr).fields
                    });
                    // serializer
                    ptr_layout.serializer = Some(Box::new(move |size: usize| {
                        if size == 0 {
                            return Ok("null".to_string());
                        }
                        let len = Self::get_length_by_mem_size(size);
                        let v = unsafe { std::slice::from_raw_parts(ptr as *const T, len) };
                        v.serialize()
                    }));
                    layout.add_field(FieldKey::Pointer, ptr_layout);
                }
                layout
            }
            fn get_ptr_by_keys(&self, keys: &[FieldKey]) -> eyre::Result<*mut u8> {
                if keys.len() > 0 {
                    eyre::ensure!(keys[0] == FieldKey::Pointer, "the key should be pointer");
                    if keys.len() == 1 {
                        return Ok(self.0 as *mut u8);
                    }

                    if keys.len() > 1 {
                        if let FieldKey::Index(i) = keys[1] {
                            if let Some(p) = unsafe { self.0.add(i).as_ref() } {
                                return p.get_ptr_by_keys(&keys[2..]);
                            }
                        }
                    }
                    // we should ensure it is not a dangling pointer
                    if let Some(p) = unsafe { self.0.as_ref() } {
                        return p.get_ptr_by_keys(&keys[1..]);
                    } else {
                        eyre::bail!("wrong location");
                    }
                }
                Ok(self as *const Self as *mut u8)
            }
        }

        impl<T: ObjFuzzable + ObjGenerate + ObjectDeserialize> ObjType for $pointer<T> {
            fn is_opaque() -> bool {
                false
            }

            fn add_fields_to_gadgets(gadgets: &mut ProgramGadgets) {
                gadgets.add_type::<T>();
            }

            fn cast_from(other: &FuzzObject) -> Box<Self> {
                let ptr = other.get_ptr_by_keys(&[FieldKey::Pointer]).unwrap();
                Box::new(Self::new(ptr as *mut T))
            }
        }

        impl<T: ObjectSerialize> ObjectSerialize for $pointer<T> {
            /// Serialize pointer
            fn serialize_obj(&self, state: &ObjectState) -> eyre::Result<String> {
                let loc = &state.get_pointer()?.pointer_location;
                if loc.is_null() {
                    Ok(format!("{}* null", $name))
                } else {
                    Ok(format!("{}* {}", $name, loc.serialize()?))
                }
            }
        }

        impl<T: ObjectTranslate> ObjectTranslate for $pointer<T> {
            fn translate_obj_to_c(
                &self,
                state: &ObjectState,
                program: &FuzzProgram,
            ) -> eyre::Result<String> {
                let loc = &state.get_pointer()?.pointer_location;
                crate::log!(trace, "pointer loc: {:?}", loc);
                let trans = loc.translate_obj_to_c(state, program)?;
                crate::log!(trace, "translate to: {}", trans);
                Ok(trans)
            }
        }

        impl<T: Serialize> Serialize for $pointer<T> {
            /// Serialize pointer
            fn serialize(&self) -> eyre::Result<String> {
                if self.0.is_null() {
                    Ok(format!("{}* null", $name))
                } else {
                    Ok(format!("{}* stub", $name))
                }
            }
        }

        impl<T: ObjFuzzable + ObjectDeserialize> ObjectDeserialize for $pointer<T> {
            fn deserialize_obj(
                de: &mut Deserializer,
                state: &mut ObjectState,
            ) -> eyre::Result<Self> {
                de.eat_token($name)?;
                de.eat_token("*")?;
                if de.strip_token("null") {
                    return Ok(Self::null(state));
                }
                if de.strip_token("stub") {
                    return Ok(Self::stub(state));
                }
                de.trim_start();
                let loc = Location::deserialize(de)?;
                return Ok(Self::loc_pointer(state, loc));
            }
        }

        impl<T: ObjFuzzable + Deserialize> Deserialize for $pointer<T> {
            fn deserialize(_de: &mut Deserializer) -> eyre::Result<Self> {
                unimplemented!();
            }
        }
    };
}

impl_fuzz_pointer!(FuzzMutPointer, "mut", true);
impl_fuzz_pointer!(FuzzConstPointer, "const", false);

impl<T> FuzzFrozenPointer<T> {
    pub fn new() -> Self {
        Self(std::ptr::null(), PhantomData)
    }
}

impl<T> Default for FuzzFrozenPointer<T> {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl<T> Sync for FuzzFrozenPointer<T> {}
unsafe impl<T> Send for FuzzFrozenPointer<T> {}

impl<T> ObjectSerialize for FuzzFrozenPointer<T> {
    fn serialize_obj(&self, state: &ObjectState) -> eyre::Result<String> {
        let _ = state.replace_weight(0);
        Ok(String::from("frozen* null"))
    }
}

impl<T> ObjectDeserialize for FuzzFrozenPointer<T> {
    fn deserialize_obj(de: &mut Deserializer, _state: &mut ObjectState) -> eyre::Result<Self> {
        de.eat_token("frozen")?;
        de.eat_token("* null")?;
        Ok(Self::new())
    }
}

impl<T> Serialize for FuzzFrozenPointer<T> {
    fn serialize(&self) -> eyre::Result<String> {
        Ok(String::from("frozen* null"))
    }
}

impl<T> Deserialize for FuzzFrozenPointer<T> {
    fn deserialize(_de: &mut Deserializer) -> eyre::Result<Self> {
        unimplemented!();
    }
}

impl<T> ObjectTranslate for FuzzFrozenPointer<T> {
    fn translate_obj_to_c(
        &self,
        _state: &ObjectState,
        _program: &FuzzProgram,
    ) -> eyre::Result<String> {
        Ok("NULL".to_string())
    }
}

impl<T> Clone for FuzzFrozenPointer<T> {
    fn clone(&self) -> Self {
        // Self(self.0, self.1)
        *self
    }
}

impl<T> Copy for FuzzFrozenPointer<T> {}

impl<T> ObjType for FuzzFrozenPointer<T> {}

impl<T> Debug for FuzzFrozenPointer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", std::any::type_name::<Self>())
    }
}

impl<T: 'static> ObjValue for FuzzFrozenPointer<T> {}

impl<T: 'static> ObjFuzzable for FuzzFrozenPointer<T> {}
