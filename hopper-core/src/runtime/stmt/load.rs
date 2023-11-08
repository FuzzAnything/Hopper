//! Load variable or constant
//! Load an object from memory which stored in the value field
//! format: load type: ident = value,

use eyre::{Context, ContextCompat};

use super::*;
use crate::{runtime::*, utils};

#[derive(Debug)]
pub struct LoadStmt {
    /// Value stored in memory
    pub value: FuzzObject,
    /// State of the value
    pub state: Box<ObjectState>,
    // is const or not
    pub is_const: bool,
}

impl StmtView for LoadStmt {
    const KEYWORD: &'static str = "load";

    fn get_value(&self) -> Option<&FuzzObject> {
        Some(&self.value)
    }

    fn eval(
        &mut self,
        used_stmts: &mut [IndexedStmt],
        resource_states: &mut ResourceStates,
    ) -> eyre::Result<()> {
        crate::log!(
            trace,
            "load `{}` at addr {:?}",
            self.value.type_name(),
            self.value.get_ptr_by_keys(&[])
        );
        let size = self.value.get_length();
        let ptr = self.value.get_ptr_by_keys(&[])?;
        resource_states.insert_ptr_size(ptr, size);
        Self::fill_pointer(&mut self.value, &self.state, used_stmts, resource_states)
    }
}

impl LoadStmt {
    pub fn new(value: FuzzObject, state: Box<ObjectState>) -> Self {
        Self {
            value,
            state,
            is_const: false,
        }
    }

    pub fn new_const(value: FuzzObject, state: Box<ObjectState>) -> Self {
        Self {
            value,
            state,
            is_const: true,
        }
    }

    pub fn new_state<T: ToString>(ident: T, ty: &str) -> Box<ObjectState> {
        Box::new(ObjectState::root(ident, utils::get_static_ty(ty)))
    }

    pub fn get_ident(&self) -> &str {
        self.state.key.as_str().unwrap()
    }

    /// Fill pointer address
    ///
    /// Address of pointer will be changed during move\ clone objects,
    /// so we assign them before executing.
    fn fill_pointer(
        load_obj: &mut FuzzObject,
        state: &ObjectState,
        used_stmts: &[IndexedStmt],
        resource_states: &mut ResourceStates,
    ) -> eyre::Result<()> {
        if let Some(ps) = &state.pointer {
            let loc = &ps.pointer_location;
            if loc.is_null() {
                return Ok(());
            }
            // address of this statement
            let fields = state.get_location_fields();
            let dst_ptr = load_obj
                .get_ptr_by_keys(fields.as_slice())
                .with_context(|| format!("dst ptr fields: {}", fields.serialize().unwrap()))?
                as *mut *mut u8;
            // it is non-null
            if let Some(stmt_index) = &loc.stmt_index {
                // the address where the stmt pointer directing
                let src_obj = stmt_index
                    .get_stmt_value(used_stmts)
                    .context("fail to find statement by index")?;
                let src_ptr = src_obj
                    .get_ptr_by_keys(loc.fields.as_slice())
                    .with_context(|| {
                        format!("src ptr fields: {}", loc.fields.serialize().unwrap())
                    })?;
                resource_states.check_pointer(src_ptr)?;
                crate::log!(
                    trace,
                    "fill `{:?}` ({}) for field `{:?}`",
                    src_ptr,
                    loc.serialize()?,
                    fields
                );
                // assign it
                unsafe { *dst_ptr = src_ptr };
            } else {
                // NULL
                unsafe { *dst_ptr = std::ptr::null_mut::<u8>() };
            }
        }
        // optimize for primitive arrays
        if let Some(st) = state.children.first() {
            if let FieldKey::Index(_) = st.key {
                if utils::is_primitive_type(st.ty) {
                    return Ok(());
                }
            }
        }
        for st in &state.children {
            Self::fill_pointer(load_obj, st, used_stmts, resource_states)?;
        }
        Ok(())
    }

    /// Check if it is a pointer that point-to freed resources.
    pub fn point_to_freed_resource(&self, program: &FuzzProgram) -> bool {
        if let Some(stmt_index) = self.state.get_pointer_stmt_index() {
            return program.stmts[stmt_index.get()].freed.is_some();
        }
        false
    }
}

impl CloneProgram for LoadStmt {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        Self::new(self.value.clone(), self.state.clone_with_program(program))
    }
}

impl From<LoadStmt> for FuzzStmt {
    fn from(stmt: LoadStmt) -> Self {
        FuzzStmt::Load(Box::new(stmt))
    }
}

impl Serialize for LoadStmt {
    fn serialize(&self) -> eyre::Result<String> {
        if self.is_const {
            Ok(format!(
                "{} const {}: {} = {}",
                Self::KEYWORD,
                self.get_ident(),
                self.value.type_name(),
                self.value.serialize_obj(&self.state)?
            ))
        } else {
            Ok(format!(
                "{} {}: {} = {}",
                Self::KEYWORD,
                self.get_ident(),
                self.value.type_name(),
                self.value.serialize_obj(&self.state)?
            ))
        }
    }
}

impl Deserialize for LoadStmt {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        // de.strip_token(Self::KEYWORD);
        let is_const = de.strip_token("const");
        de.trim_start();
        let ident = de.next_token_until(":")?;
        let ty = de.next_token_until(" =")?;
        let mut state = Self::new_state(ident, ty);
        let value = read_value(de, ty, &mut state)?;
        Ok(Self {
            value,
            state,
            is_const,
        })
    }
}