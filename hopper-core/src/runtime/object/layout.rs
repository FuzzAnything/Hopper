//! Layout of an object for fuzzing
//! It describe the fields of structure and their types,
//! we consider pointers but ignore arrays in our implementation

use std::{cell::RefCell, fmt};

use eyre::ContextCompat;

use crate::{
    feedback::ResourceStates, utils, FieldEqual, FieldKey, HopperError, LocFields,
    Serialize,
};

type LazyLoaderHolder = (
    RefCell<Vec<ObjectLayout>>,
    Box<dyn Fn(usize) -> Vec<ObjectLayout>>,
);

/// Object's field-type layout
pub struct ObjectLayout {
    pub key: FieldKey,
    pub type_name: &'static str,
    pub ptr: *mut u8,
    pub is_union: bool,
    pub fields: Vec<ObjectLayout>,
    // used for lazy get fields
    pub lazy_loader: Option<LazyLoaderHolder>,
    // used for serialize current object
    pub serializer: Option<Box<dyn Fn(usize) -> eyre::Result<String>>>,
}

impl fmt::Debug for ObjectLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectLayout")
            .field("key", &self.key)
            .field("type_name", &self.type_name)
            .field("ptr", &self.ptr)
            .finish()
    }
}

impl ObjectLayout {
    pub fn root(type_name: &'static str, ptr: *mut u8) -> Self {
        Self {
            key: FieldKey::Root("layout".to_string()),
            ptr,
            type_name,
            is_union: false,
            fields: vec![],
            lazy_loader: None,
            serializer: None,
        }
    }

    pub fn set_lazy_loader<T: Fn(usize) -> Vec<ObjectLayout> + 'static>(&mut self, f: T) {
        self.lazy_loader = Some((RefCell::new(vec![]), Box::new(f)))
    }

    /// Get fields with reseource states
    /// it will expand pointer's fields
    pub fn get_fields_with_rs(&self, resource_states: &ResourceStates) -> &[ObjectLayout] {
        if let Some((holder, f)) = &self.lazy_loader {
            if holder.borrow().is_empty() {
                let size = resource_states.get_ptr_size(self.ptr).unwrap_or(1);
                // crate::log!(trace, "type: {:?}, ptr: {:?}, size: {}", self.type_name, self.ptr, size);
                let fields = f(size);
                holder.replace(fields);
            }
            return unsafe { holder.as_ptr().as_ref().unwrap() };
        }
        &self.fields
    }

    /// Get fields directly, without expanding pointer's fields
    pub fn get_ir_fields(&self) -> &[ObjectLayout] {
        &self.fields
    }

    /// Get Child
    pub fn get_child<F: FieldEqual + std::fmt::Debug>(&self, key: F) -> eyre::Result<&Self> {
        self.fields
            .iter()
            .find(|c| key.eq_field(&c.key))
            .with_context(|| format!("fail to find child layout `{:?}` in `{:?}`", key, self.key))
    }

    /// Get reference of child's state by keys recursively
    pub fn get_child_by_fields(&self, fields: &[FieldKey]) -> Result<&Self, HopperError> {
        if fields.is_empty() {
            return Ok(self);
        }

        let layout = match self.get_child(&fields[0]) {
            Ok(l) => l,
            Err(r) => {
                if self.is_union {
                    return Err(HopperError::UnionErr);
                } else {
                    return Err(HopperError::FieldNotFound(r.to_string()));
                }
            }
        };

        layout.get_child_by_fields(&fields[1..])
    }

    /// Add fields
    pub fn add_field<K: Into<FieldKey>>(&mut self, field_key: K, layout: ObjectLayout) {
        let mut layout = layout;
        layout.key = field_key.into();
        self.fields.push(layout);
    }

    /// Check if the layout is revisit (Pointer)
    pub fn is_revisited(&self, visited_pointers: &mut Vec<*mut u8>) -> bool {
        // Only pointer type has such cases
        if self.key == FieldKey::Pointer {
            if visited_pointers.contains(&self.ptr) {
                return true;
            }
            visited_pointers.push(self.ptr);
        }
        false
    }

    /// Find particular pointer in the object
    pub fn find_ptr(&self, ptr: *mut u8, resource_states: &ResourceStates) -> Option<LocFields> {
        let mut cur_path = LocFields::default();
        let mut visited_pointers = vec![];
        self.find_ptr_in_layout(&mut visited_pointers, &mut cur_path, ptr, resource_states)
    }

    fn find_ptr_in_layout(
        &self,
        visited_pointers: &mut Vec<*mut u8>,
        cur_path: &mut LocFields,
        ptr: *mut u8,
        resource_states: &ResourceStates,
    ) -> Option<LocFields> {
        if self.is_revisited(visited_pointers) {
            return None;
        }
        if self.ptr == ptr {
            return Some(std::mem::take(cur_path));
        }
        for layout in self.get_fields_with_rs(resource_states) {
            cur_path.push(layout.key.clone());
            let found = layout.find_ptr_in_layout(visited_pointers, cur_path, ptr, resource_states);
            if found.is_some() {
                return found;
            }
            cur_path.pop();
        }
        None
    }

    /// check pointer by closure
    pub fn check_ptr(&self, resource_states: &ResourceStates, depth: usize) -> eyre::Result<()> {
        // since we will skip using freed canary poitners in our generating,
        // and the pointers is `false` freed actually (we hook and enfore to free them),
        // so we do not need check them here.
        if depth > 5 || crate::is_in_canary(self.ptr) {
            return Ok(());
        }
        resource_states.check_pointer(self.ptr)?;
        if self.key == FieldKey::Pointer && crate::utils::is_primitive_type(self.type_name) {
            return Ok(());
        }
        for layout in self.get_fields_with_rs(resource_states) {
            layout.check_ptr(resource_states, depth + 1)?;
        }
        Ok(())
    }

    /// Serialzie pointers in return object
    pub fn serialize_return_object_pointers(
        &self,
        resource_states: &ResourceStates,
    ) -> eyre::Result<Vec<String>> {
        let mut found = vec![];
        let mut visited_pointers = vec![];
        let mut cur_path = LocFields::default();
        self.serialize_pointers_in_return_inner(
            &mut found,
            &mut visited_pointers,
            &mut cur_path,
            resource_states,
        )?;
        Ok(found)
    }

    fn serialize_pointers_in_return_inner(
        &self,
        found: &mut Vec<String>,
        visited_pointers: &mut Vec<*mut u8>,
        cur_path: &mut LocFields,
        resource_states: &ResourceStates,
    ) -> eyre::Result<()> {
        if self.is_revisited(visited_pointers) {
            return Ok(());
        }
        if let Some(f) = &self.serializer {
            let size = resource_states.get_ptr_size(self.ptr);
            if size.is_none() && utils::is_primitive_type(self.type_name) {
                return Ok(());
            }
            let size = size.unwrap_or(1);
            if utils::is_opaque_type(self.type_name) {
                return Ok(());
            }
            if size > 0 {
                let content = f(size)?;
                found.push(format!(
                    "({}, {}, {})",
                    cur_path.serialize()?,
                    utils::vec_type(self.type_name),
                    content
                ));
            }
        }
        // for custom type that may contain pointers, we only
        // serialize first element in list
        let keep_first_ptr_element =
            self.key == FieldKey::Pointer && utils::is_primitive_type(self.type_name);
        for layout in self.get_fields_with_rs(resource_states) {
            cur_path.push(layout.key.clone());
            layout.serialize_pointers_in_return_inner(
                found,
                visited_pointers,
                cur_path,
                resource_states,
            )?;
            cur_path.pop();
            if keep_first_ptr_element {
                break;
            }
        }
        Ok(())
    }

}
