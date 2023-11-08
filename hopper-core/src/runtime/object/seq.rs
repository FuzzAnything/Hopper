//! Describe array's fuzzing trait
//! arrays are: [T; N], where T is fuzzable

use std::mem::MaybeUninit;

use super::*;
use crate::{utils, ObjGenerate};

impl<T: ObjFuzzable + ObjGenerate + Clone + ObjectDeserialize, const N: usize> ObjFuzzable
    for [T; N]
{
}

impl<T: ObjFuzzable + ObjGenerate + Clone> ObjFuzzable for Vec<T> {}

impl<T: ObjValue> ObjValue for [T] {
    fn get_layout(&self, fold_ptr: bool) -> ObjectLayout {
        let mut layout = ObjectLayout::root(self.type_name(), self.as_ptr() as *mut u8);
        for (i, v) in self.iter().enumerate() {
            layout.add_field(FieldKey::Index(i), v.get_layout(fold_ptr));
        }
        layout
    }

    fn get_ptr_by_keys(&self, keys: &[FieldKey]) -> eyre::Result<*mut u8> {
        if keys.is_empty() {
            return Ok(self as *const Self as *mut u8);
        }
        if let FieldKey::Index(i) = &keys[0] {
            return self[*i].get_ptr_by_keys(&keys[1..]);
        }
        eyre::bail!("Key `{:?}` is not fit for sequence", keys);
    }
    fn get_length(&self) -> usize {
        self.len()
    }
}

impl<T: ObjValue, const N: usize> ObjValue for [T; N] {
    fn get_layout(&self, fold_ptr: bool) -> ObjectLayout {
        let mut layout = self.as_slice().get_layout(fold_ptr);
        layout.type_name = self.type_name();
        layout
    }
    fn get_ptr_by_keys(&self, keys: &[FieldKey]) -> eyre::Result<*mut u8> {
        self.as_slice().get_ptr_by_keys(keys)
    }
    fn get_length(&self) -> usize {
        N
    }
}

impl<T: ObjFuzzable + ObjGenerate + ObjectDeserialize, const N: usize> ObjType for [T; N] {
    fn is_opaque() -> bool {
        // zero length array
        // https://doc.rust-lang.org/nomicon/exotic-sizes.html#zero-sized-types-zsts
        N == 0
    }

    fn add_fields_to_gadgets(gadgets: &mut ProgramGadgets) {
        gadgets.add_type::<T>();
    }
}

impl<T: ObjValue> ObjValue for Vec<T> {
    fn get_layout(&self, fold_ptr: bool) -> ObjectLayout {
        let mut layout = self.as_slice().get_layout(fold_ptr);
        layout.type_name = self.type_name();
        layout
    }
    fn get_ptr_by_keys(&self, keys: &[FieldKey]) -> eyre::Result<*mut u8> {
        self.as_slice().get_ptr_by_keys(keys)
    }
    fn get_length(&self) -> usize {
        self.len()
    }
}

impl<T: ObjType> ObjType for Vec<T> {}

impl<T: ObjectSerialize, const N: usize> ObjectSerialize for [T; N] {
    fn serialize_obj(&self, state: &ObjectState) -> eyre::Result<String> {
        let mut buf = String::new();
        buf.push('[');
        for (i, v) in self.iter().enumerate() {
            buf.push_str(&v.serialize_obj(state.get_child(i)?)?);
            buf.push_str(", ");
        }
        buf.push(']');
        Ok(buf)
    }
}

impl<T: Serialize, const N: usize> Serialize for [T; N] {
    fn serialize(&self) -> eyre::Result<String> {
        let mut buf = String::new();
        buf.push('[');
        for v in self.iter() {
            buf.push_str(&v.serialize()?);
            buf.push_str(", ");
        }
        buf.push(']');
        Ok(buf)
    }
}

impl<T: ObjectTranslate, const N: usize> ObjectTranslate for [T; N] {
    fn translate_obj_to_c(
        &self,
        state: &ObjectState,
        program: &FuzzProgram,
    ) -> eyre::Result<String> {
        let mut buf = String::new();
        buf.push('{');
        for (i, v) in self.iter().enumerate() {
            buf.push_str(&v.translate_obj_to_c(state.get_child(i)?, program)?);
            buf.push_str(", ");
        }
        buf.push('}');
        Ok(buf)
    }
}

impl<T: ObjectSerialize> ObjectSerialize for Vec<T> {
    fn serialize_obj(&self, state: &ObjectState) -> eyre::Result<String> {
        if self.len() > 16 && utils::is_byte(std::any::type_name::<T>()) {
            let mut buf = String::new();
            buf.push_str("bvec(");
            buf.push_str(&self.len().to_string());
            buf.push_str(")[\"");
            serialize_bytes(&mut buf, self);
            buf.push_str("\"]");
            return Ok(buf);
        }
        self.as_slice().serialize_obj(state)
    }
}

impl<T: Serialize> Serialize for Vec<T> {
    fn serialize(&self) -> eyre::Result<String> {
        self.as_slice().serialize()
    }
}

impl<T: ObjectTranslate> ObjectTranslate for Vec<T> {
    fn translate_obj_to_c(
        &self,
        state: &ObjectState,
        program: &FuzzProgram,
    ) -> eyre::Result<String> {
        let mut buf = String::new();
        buf.push('{');
        for (i, v) in self.iter().enumerate() {
            buf.push_str(&v.translate_obj_to_c(state.get_child(i)?, program)?);
            buf.push_str(", ");
        }
        buf.push('}');
        Ok(buf)
    }
}

impl<T: Serialize> Serialize for [T] {
    fn serialize(&self) -> eyre::Result<String> {
        // serialize like vec<T>
        let mut buf = String::new();
        buf.push_str("vec(");
        buf.push_str(&self.len().to_string());
        buf.push_str(")[");
        for v in self.iter() {
            buf.push_str(&v.serialize()?);
            buf.push_str(", ");
        }
        buf.push(']');
        Ok(buf)
    }
}

impl<T: ObjectSerialize> ObjectSerialize for [T] {
    fn serialize_obj(&self, state: &ObjectState) -> eyre::Result<String> {
        let mut buf = String::new();
        buf.push_str("vec(");
        buf.push_str(&self.len().to_string());
        buf.push_str(")[");
        for (i, v) in self.iter().enumerate() {
            buf.push_str(&v.serialize_obj(state.get_child(i)?)?);
            buf.push_str(", ");
        }
        buf.push(']');
        Ok(buf)
    }
}

fn deserialize_array<T, const N: usize>(
    de: &mut Deserializer,
    mut f: impl FnMut(&mut Deserializer) -> eyre::Result<T>,
) -> eyre::Result<[T; N]> {
    if N == 0 {
        unsafe {
            return Ok(std::mem::zeroed());
        }
    }
    de.eat_token("[")?;
    let mut output: MaybeUninit<[T; N]> = MaybeUninit::uninit();
    let arr_ptr = output.as_mut_ptr() as *mut T;
    for i in 0..N {
        let element = f(de)?;
        unsafe {
            arr_ptr.add(i).write(element);
        }
        de.eat_token(",")?;
    }
    de.eat_token("]")?;
    let val = unsafe { output.assume_init() };
    Ok(val)
}

impl<T: ObjectDeserialize + ObjGenerate + ObjValue, const N: usize> ObjectDeserialize for [T; N] {
    fn deserialize_obj(de: &mut Deserializer, state: &mut ObjectState) -> eyre::Result<Self> {
        deserialize_array(de, |de| deserialize_element_for_slice::<T>(de, state))
    }
}

impl<T: Deserialize + ObjGenerate, const N: usize> Deserialize for [T; N] {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        deserialize_array(de, |de| T::deserialize(de))
    }
}

fn deserialize_vec<T>(
    de: &mut Deserializer,
    mut f: impl FnMut(&mut Deserializer) -> eyre::Result<T>,
) -> eyre::Result<Vec<T>> {
    de.eat_token("vec(")?;
    let len: usize = de.parse_number()?;
    de.eat_token(")[")?;
    let mut list = Vec::<T>::with_capacity(len);
    for _ in 0..len {
        let element = f(de)?;
        list.push(element);
        de.eat_token(",")?;
    }
    de.eat_token("]")?;
    Ok(list)
}

impl<T: ObjectDeserialize + ObjGenerate + ObjValue> ObjectDeserialize for Vec<T> {
    fn deserialize_obj(de: &mut Deserializer, state: &mut ObjectState) -> eyre::Result<Self> {
        if de.strip_token("bvec(") {
            let len: usize = de.parse_number()?;
            de.eat_token(")[\"")?;
            let mut list = Vec::<T>::with_capacity(len);
            let buf = de.next_token_until("\"]")?;
            let remaining = list.spare_capacity_mut(); // `&mut [MaybeUninit<u8>]`
            deserialize_bytes(remaining, buf)?;
            // add state
            for i in 0..len {
                let _ = state
                    .add_child(i, std::any::type_name::<T>())
                    .last_child_mut()?;
            }
            unsafe { list.set_len(len) };
            return Ok(list);
        }
        deserialize_vec(de, |de| deserialize_element_for_slice::<T>(de, state))
    }
}

impl<T: Deserialize> Deserialize for Vec<T> {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        deserialize_vec(de, |de| T::deserialize(de))
    }
}

/// Deserialize element for slice
pub fn deserialize_element_for_slice<T: ObjectDeserialize + ObjGenerate + ObjValue>(
    de: &mut Deserializer,
    state: &mut ObjectState,
) -> eyre::Result<T> {
    let sub_state = state
        .add_child(state.children.len(), std::any::type_name::<T>())
        .last_child_mut()?;
    let element = T::deserialize_obj(de, sub_state)?;
    // check_seq_element_state(element.type_name(), sub_state);
    Ok(element)
}

/*
#[inline]
pub fn check_seq_element_state(type_name: &str, state: &ObjectState) {
    // avoid float det
    if type_name == "f32" || type_name == "f64" {
        state.done_deterministic_itself();
    }
}
*/

impl ObjectSerialize for String {
    fn serialize_obj(&self, _state: &ObjectState) -> eyre::Result<String> {
        self.serialize()
    }
}

impl Serialize for String {
    fn serialize(&self) -> eyre::Result<String> {
        Ok(format!("\"{}\"", &self))
    }
}

impl ObjectDeserialize for String {
    fn deserialize_obj(de: &mut Deserializer, _state: &mut ObjectState) -> eyre::Result<Self> {
        Self::deserialize(de)
    }
}

impl Deserialize for String {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        de.eat_token("\"")?;
        let val = de.next_token_until("\"")?;
        Ok(val.into())
    }
}

#[test]
fn test_vec_serde() {
    let s = "vec(3)[1, 2, 3, ]";
    let mut state = ObjectState::root("test", "Vec<i32>");
    let mut de = Deserializer::new(s, None);
    let v2 = Vec::<i32>::deserialize_obj(&mut de, &mut state).unwrap();
    let s2 = ObjectSerialize::serialize_obj(&v2, &state).unwrap();
    assert_eq!(s, s2);
}

pub fn serialize_bytes<T>(buf: &mut String, seq: &[T]) {
    let size = std::mem::size_of_val(seq);
    let bytes = unsafe { std::slice::from_raw_parts(seq.as_ptr() as *const u8, size) };
    base64::encode_config_buf(bytes, base64::STANDARD, buf);
}

pub fn deserialize_bytes<T>(buf: &mut [T], raw: &str) -> eyre::Result<()> {
    let size = std::mem::size_of_val(buf);
    let buf = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, size) };
    base64::decode_config_slice(raw, base64::STANDARD, buf)?;
    Ok(())
}

#[test]
fn test_base64_seq() {
    let seq = vec![1, -1, 771230];
    let mut buf = String::new();
    serialize_bytes(&mut buf, &seq);
    println!("buf: {buf}");
    let mut seq2 = vec![0; 3];
    deserialize_bytes(&mut seq2, &buf).unwrap();
    println!("seq2: {seq2:?}");
    assert_eq!(seq, seq2);
}
