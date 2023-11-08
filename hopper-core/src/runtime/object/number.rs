//! Describe numbers' fuzzing trait
//! numbers are: integers and floats

use eyre::ContextCompat;

use crate::impl_obj_fuzz;

use super::*;

impl_obj_fuzz!(u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, f32, f64, char, bool, usize, isize);

macro_rules! impl_fuzz_value {
    ( $($name:ident),* ) => {
        $(
            impl ObjValue for $name {
                fn is_zero(&self) -> bool {
                    let zero: Self = unsafe { std::mem::zeroed() };
                    self == &zero
                }
            }
       )*
    }
}

impl_fuzz_value!(u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, f32, f64, char, bool, usize, isize);

macro_rules! impl_fuzz_type {
    ( $($name:ident),* ) => {
        $(
            impl ObjType for $name {
                fn is_primitive() -> bool {
                    true
                }
            }
       )*
    }
}
impl_fuzz_type!(u8, i8, u16, i16, u128, i128, f32, f64, char, bool, usize, isize);

macro_rules! impl_fuzz_type_fd {
    ( $($name:ident),* ) => {
        $(
            impl ObjType for $name {
                fn is_primitive() -> bool {
                    true
                }
                fn cast_from(other: &FuzzObject) -> Box<Self> {
                    if let Some(fd) = other.downcast_ref::<FileFd>() {
                        return Box::new(fd.inner() as $name);
                    }
                    Box::new(0)
                }
            }
       )*
    }
}
impl_fuzz_type_fd!(u32, i32, u64, i64);


macro_rules! impl_number_serde {
    ( $($name:ident),* ) => {
        $(
            impl ObjectSerialize for $name {
                fn serialize_obj(&self, _state: &ObjectState) -> eyre::Result<String> {
                    Ok(self.to_string())
                }
            }
            impl Serialize for $name {
                fn serialize(&self) -> eyre::Result<String> {
                    Ok(self.to_string())
                }
            }
            impl ObjectDeserialize for $name {
                fn deserialize_obj(de: &mut Deserializer, _state: &mut ObjectState) -> eyre::Result<Self> {
                    de.parse_number()
                }
            }
            impl Deserialize for $name {
                fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
                    de.parse_number()
                }
            }
       )*
    }
}

impl_number_serde!(u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, usize, isize);

macro_rules! impl_number_translate {
    ( $($name:ident),* ) => {
        $(
            impl ObjectTranslate for $name {}
        )*
    }
}

impl_number_translate!(u8, i8, u16, i16, u32, i32, u128, i128, bool, char, usize, isize);

impl ObjectTranslate for u64 {
    fn translate_obj_to_c(
        &self,
        _state: &ObjectState,
        _program: &FuzzProgram,
    ) -> eyre::Result<String> {
        Ok(self.to_string() + "ULL")
    }
}

impl ObjectTranslate for i64 {
    fn translate_obj_to_c(
        &self,
        _state: &ObjectState,
        _program: &FuzzProgram,
    ) -> eyre::Result<String> {
        Ok(self.to_string() + "LL")
    }
}

macro_rules! impl_float_serde {
    ( $($name:ident),* ) => {
        $(
            impl ObjectSerialize for $name {
                fn serialize_obj(&self, _state: &ObjectState) -> eyre::Result<String> {
                    Ok(self.to_string())
                }
            }
            impl Serialize for $name {
                fn serialize(&self) -> eyre::Result<String> {
                    Ok(self.to_string())
                }
            }
            impl ObjectDeserialize for $name {
                fn deserialize_obj(de: &mut Deserializer, _state: &mut ObjectState) -> eyre::Result<Self> {
                    de.parse_float()
                }
            }
            impl Deserialize for $name {
                fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
                    de.parse_float()
                }
            }
            impl ObjectTranslate for $name {
                fn translate_obj_to_c(&self, _state: &ObjectState, _program: &FuzzProgram) -> eyre::Result<String> {
                    let val = self.to_string();
                    match val.as_str() {
                        "NaN" => Ok("NAN".to_string()),
                        "inf" => Ok("INFINITY".to_string()),
                        "-inf" => Ok("INFINITY".to_string()),
                        _ => {
                            if !val.contains('.') {
                                return Ok(val + ".0");
                            }
                            Ok(val)
                        }
                    }

                }
            }
       )*
    }
}

impl_float_serde!(f32, f64);

impl ObjectSerialize for char {
    fn serialize_obj(&self, _state: &ObjectState) -> eyre::Result<String> {
        self.serialize()
    }
}

impl Serialize for char {
    fn serialize(&self) -> eyre::Result<String> {
        Ok(format!("\'{self}\'"))
    }
}

impl ObjectDeserialize for char {
    fn deserialize_obj(de: &mut Deserializer, _state: &mut ObjectState) -> eyre::Result<Self> {
        Self::deserialize(de)
    }
}

impl Deserialize for char {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        eyre::ensure!(de.next_char() == Some('\''), "next char is quote");
        let c = de.next_char().context("Char is not exisited")?;
        eyre::ensure!(de.next_char() == Some('\''), "next char is quote");
        Ok(c)
    }
}

impl ObjectSerialize for bool {
    fn serialize_obj(&self, _state: &ObjectState) -> eyre::Result<String> {
        self.serialize()
    }
}

impl Serialize for bool {
    fn serialize(&self) -> eyre::Result<String> {
        if *self {
            Ok("T".to_string())
        } else {
            Ok("F".to_string())
        }
    }
}

impl ObjectDeserialize for bool {
    fn deserialize_obj(de: &mut Deserializer, _state: &mut ObjectState) -> eyre::Result<Self> {
        Self::deserialize(de)
    }
}

impl Deserialize for bool {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        let c = de.next_char().context("buffer is empty")?;
        match c {
            'T' => Ok(true),
            'F' => Ok(false),
            _ => eyre::bail!("Unknown token for boolean"),
        }
    }
}
