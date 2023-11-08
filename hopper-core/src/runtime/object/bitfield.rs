use super::*;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HopperBindgenBitfieldUnit<Storage> {
    pub storage: Storage,
}

impl<Storage: ObjFuzzable + Clone> ObjFuzzable for HopperBindgenBitfieldUnit<Storage> {}

impl<Storage: ObjValue> ObjValue for HopperBindgenBitfieldUnit<Storage> {}

impl<Storage: ObjType> ObjType for HopperBindgenBitfieldUnit<Storage> {}

impl<Storage: Serialize> Serialize for HopperBindgenBitfieldUnit<Storage> {
    fn serialize(&self) -> eyre::Result<String> {
        Ok(format!("bitfield {}", self.storage.serialize()?))
    }
}

impl<Storage: ObjectSerialize> ObjectSerialize for HopperBindgenBitfieldUnit<Storage> {
    fn serialize_obj(&self, state: &ObjectState) -> eyre::Result<String> {
        Ok(format!(
            "bitfield {}",
            self.storage.serialize_obj(state.last_child()?)?
        ))
    }
}

impl<Storage: ObjectTranslate> ObjectTranslate for HopperBindgenBitfieldUnit<Storage> {
    fn translate_obj_to_c(
        &self,
        state: &ObjectState,
        program: &FuzzProgram,
    ) -> eyre::Result<String> {
        self.storage.translate_obj_to_c(state.last_child()?, program)
    }
}

impl<Storage: Deserialize> Deserialize for HopperBindgenBitfieldUnit<Storage> {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        de.eat_token("bitfield")?;
        let storage = Storage::deserialize(de)?;
        Ok(Self{ storage })
    }
}

impl<Storage: ObjectDeserialize> ObjectDeserialize for HopperBindgenBitfieldUnit<Storage> {
    fn deserialize_obj(de: &mut Deserializer, state: &mut ObjectState) -> eyre::Result<Self> {
        de.eat_token("bitfield")?;
        let sub_state = state
            .add_child(FieldKey::Field("storage".to_string()), std::any::type_name::<Storage>())
            .last_child_mut()?;
        let storage = Storage::deserialize_obj(de, sub_state)?;
        Ok(Self{ storage })
    }
}

impl<Storage> HopperBindgenBitfieldUnit<Storage> {
    #[inline]
    pub const fn new(storage: Storage) -> Self {
        Self { storage }
    }
}
impl<Storage> HopperBindgenBitfieldUnit<Storage>
where
    Storage: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    pub fn get_bit(&self, index: usize) -> bool {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = self.storage.as_ref()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        byte & mask == mask
    }
    #[inline]
    pub fn set_bit(&mut self, index: usize, val: bool) {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = &mut self.storage.as_mut()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        if val {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
    #[inline]
    pub fn get(&self, bit_offset: usize, bit_width: u8) -> u64 {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        let mut val = 0;
        for i in 0..(bit_width as usize) {
            if self.get_bit(i + bit_offset) {
                let index = if cfg!(target_endian = "big") {
                    bit_width as usize - 1 - i
                } else {
                    i
                };
                val |= 1 << index;
            }
        }
        val
    }
    #[inline]
    pub fn set(&mut self, bit_offset: usize, bit_width: u8, val: u64) {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        for i in 0..(bit_width as usize) {
            let mask = 1 << i;
            let val_bit_is_set = val & mask == mask;
            let index = if cfg!(target_endian = "big") {
                bit_width as usize - 1 - i
            } else {
                i
            };
            self.set_bit(index + bit_offset, val_bit_is_set);
        }
    }
}