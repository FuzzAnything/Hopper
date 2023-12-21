use std::fmt;

use super::*;

/// Field key
/// use for describe the place/location of a value inside a *statement*
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FieldKey {
    Index(usize),
    Field(String),
    Root(String),
    Pointer,
    Option,
}

impl FieldKey {
    pub fn as_str(&self) -> eyre::Result<&str> {
        match self {
            FieldKey::Root(s) => Ok(s),
            FieldKey::Field(s) => Ok(s),
            FieldKey::Index(_i) => Ok("$index"),
            FieldKey::Pointer => Ok("$ptr"),
            FieldKey::Option => Ok("$opt"),
        }
    }

    pub fn as_usize(&self) -> eyre::Result<usize> {
        match self {
            FieldKey::Index(i) => Ok(*i),
            _ => eyre::bail!("field is not index!"),
        }
    }

    pub fn is_index(&self) -> bool {
        matches!(self, FieldKey::Index(_))
    }

    pub fn union_root() -> Self {
        Self::Root(crate::UNION_ROOT.to_string())
    }

    pub fn is_union_root(&self) -> bool {
        if let FieldKey::Root(tag) = self {
            return tag == crate::UNION_ROOT;
        }
        false
    }
}

impl From<usize> for FieldKey {
    fn from(i: usize) -> Self {
        FieldKey::Index(i)
    }
}

impl From<String> for FieldKey {
    fn from(f: String) -> Self {
        FieldKey::Field(f)
    }
}

impl From<&str> for FieldKey {
    fn from(f: &str) -> Self {
        FieldKey::Field(f.to_string())
    }
}

pub trait FieldEqual {
    fn eq_field(&self, entry: &FieldKey) -> bool;
    fn as_field_key(&self) -> FieldKey;
}

impl FieldEqual for usize {
    fn eq_field(&self, entry: &FieldKey) -> bool {
        match entry {
            FieldKey::Index(i) => i == self,
            _ => false,
        }
    }
    fn as_field_key(&self) -> FieldKey {
        FieldKey::Index(*self)
    }
}

impl FieldEqual for &str {
    fn eq_field(&self, entry: &FieldKey) -> bool {
        match entry {
            FieldKey::Field(f) => f == self,
            _ => false,
        }
    }
    fn as_field_key(&self) -> FieldKey {
        FieldKey::Field(self.to_string())
    }
}

impl FieldEqual for &FieldKey {
    fn eq_field(&self, entry: &FieldKey) -> bool {
        *self == entry
    }
    fn as_field_key(&self) -> FieldKey {
        (*self).clone()
    }
}

/// Location
/// use for describe the place/location of a value inside a *program*
#[derive(Debug, Clone, PartialEq)]
pub struct Location {
    pub stmt_index: Option<StmtIndex>,
    pub fields: LocFields,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WeakLocation {
    pub stmt_index: Option<WeakStmtIndex>,
    pub fields: LocFields,
}

pub trait RcLocation {
    /// Get the index of statement
    fn get_index(&self) -> eyre::Result<&dyn RcIndex>;
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct LocFields {
    pub list: Vec<FieldKey>,
}

impl LocFields {
    pub fn new(list: Vec<FieldKey>) -> Self {
        Self { list }
    }

    pub fn push(&mut self, item: FieldKey) {
        self.list.push(item);
    }

    pub fn pop(&mut self) {
        self.list.pop();
    }

    pub fn as_slice(&self) -> &[FieldKey] {
        self.list.as_slice()
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
}

impl RcLocation for Location {
    fn get_index(&self) -> eyre::Result<&dyn RcIndex> {
        Ok(self
            .stmt_index
            .as_ref()
            .ok_or_else(|| eyre::eyre!("loc is null"))?)
    }
}

impl RcLocation for WeakLocation {
    fn get_index(&self) -> eyre::Result<&dyn RcIndex> {
        Ok(self
            .stmt_index
            .as_ref()
            .ok_or_else(|| eyre::eyre!("loc is null"))?)
    }
}

impl Location {
    /// Create new location
    pub fn new(stmt_index: StmtIndex, fields: LocFields) -> Self {
        Self {
            stmt_index: Some(stmt_index),
            fields,
        }
    }

    /// Create a null location
    pub fn null() -> Self {
        Self {
            stmt_index: None,
            fields: LocFields::default(),
        }
    }

    /// Create a location directing to a statement
    pub fn stmt(stmt_index: StmtIndex) -> Self {
        Self {
            stmt_index: Some(stmt_index),
            fields: LocFields::default(),
        }
    }

    /// Use this location in other places.
    pub fn use_loc(&self) -> Self {
        Self {
            stmt_index: self.stmt_index.as_ref().map(|i| i.use_index()),
            fields: self.fields.clone(),
        }
    }

    /// Duplicate a new loc with the same index (but with different reference)
    pub fn dup(&self) -> Self {
        Self {
            stmt_index: self.stmt_index.as_ref().map(|i| i.dup()),
            fields: self.fields.clone(),
        }
    }

    /// Set this location with a new statement index
    pub fn set_index(&mut self, index: StmtIndex) {
        self.stmt_index = Some(index);
    }

    /// Is the location is null or not
    pub fn is_null(&self) -> bool {
        self.stmt_index.is_none()
    }

    /// Convert to weak location
    pub fn to_weak_loc(&self) -> WeakLocation {
        WeakLocation {
            stmt_index: self.stmt_index.as_ref().map(|i| i.downgrade()),
            fields: self.fields.clone(),
        }
    }

    /// Compare with weak location
    pub fn compare_weak(&self, weak_loc: &WeakLocation) -> bool {
        let weak_index = weak_loc.stmt_index.as_ref().map(|i| i.upgrade().unwrap());
        self.stmt_index == weak_index && self.fields == weak_loc.fields
    }
}

impl WeakLocation {
    /// Create a null location
    pub fn null() -> Self {
        Self {
            stmt_index: None,
            fields: LocFields::default(),
        }
    }

    /// Is the location is null or not
    pub fn is_null(&self) -> bool {
        self.stmt_index.is_none()
    }

    /// Set this location with a new statement index
    pub fn set_index(&mut self, index: StmtIndex) {
        self.stmt_index = Some(index.downgrade());
    }

    /// Check if the location is released or not
    pub fn is_released(&self) -> bool {
        if let Some(index) = &self.stmt_index {
            return index.is_released();
        }
        false
    }
}

const FIELD_SEP: &str = ".";

impl Serialize for LocFields {
    fn serialize(&self) -> eyre::Result<String> {
        let mut buf = String::new();
        buf.push('[');
        for entry in self.list.iter() {
            if buf.len() > 1 {
                buf.push_str(FIELD_SEP)
            }
            buf.push_str(&entry.serialize()?);
        }
        buf.push(']');
        Ok(buf)
    }
}

impl Serialize for FieldKey {
    fn serialize(&self) -> eyre::Result<String> {
        let buf = match self {
            FieldKey::Index(i) => format!("${i}"),
            FieldKey::Field(f) => f.to_string(),
            FieldKey::Root(i) => format!("@{i}"),
            FieldKey::Pointer => "&".to_string(),
            FieldKey::Option => "?".to_string(),
        };
        Ok(buf)
    }
}

impl LocFields {
    /// Append suffix after it
    pub fn with_suffix(&self, suffix: LocFields) -> Self {
        let mut full = self.clone();
        full.list.extend(suffix.list);
        full
    }

    /// Strip pointer field suffix if has
    pub fn strip_pointer_suffix(&mut self) -> bool {
        if self.list.last() == Some(&FieldKey::Pointer) {
            self.pop();
            true
        } else {
            false
        }
    }

     /// Strip pointer field prefix if has
     pub fn strip_pointer_prefix(&mut self) -> bool {
        if self.list.first() == Some(&FieldKey::Pointer) {
            self.pop();
            true
        } else {
            false
        }
    }

    /// Strip index field after pointer field if has
    pub fn strip_index_suffix(&mut self) -> bool {
        if self
            .list
            .as_slice()
            .ends_with(&[FieldKey::Pointer, FieldKey::Index(0)])
        {
            self.pop();
            true
        } else {
            false
        }
    }

    /// Get a location for refining
    pub fn to_loc_for_refining(
        &self,
        program: &FuzzProgram,
        index: &StmtIndex,
        prefix: &LocFields,
    ) -> Option<Location> {
        // special for pointer argument
        let mut sub_list: Vec<&[FieldKey]> = self.list.split(|f| f == &FieldKey::Pointer).collect();
        if sub_list.is_empty() {
            return None;
        }
        let last_sub_list = sub_list.pop().unwrap();
        let mut suffix_fields = Vec::from(last_sub_list);
        let mut index = index;
        'loop_sub: for i in 0..sub_list.len() {
            let sub_fields = sub_list[i];
            // crate::log_trace!("cur_sub_list: {sub_fields:?}");
            match &program.stmts[index.get()].stmt {
                FuzzStmt::Load(load) => match load.state.get_child_by_fields(sub_fields) {
                    Ok(sub_state) => {
                        if let Some(new_index) = sub_state.get_pointer_stmt_index() {
                            // crate::log_trace!("load {new_index} from {index}");
                            index = new_index;
                            continue;
                        }
                    }
                    Err(err) => {
                        if matches!(
                            err,
                            crate::HopperError::UnionErr | crate::HopperError::IndexNotExist
                        ) {
                            return None;
                        } else {
                            unreachable!("err: {}", err);
                        }
                    }
                },
                FuzzStmt::Call(_call_stmt) => {
                    crate::log_trace!("call {index}, find its updates");
                    for is in &program.stmts[index.get()..] {
                        let FuzzStmt::Update(update_stmt) = &is.stmt else {
                            continue;
                        };
                        let Some(dst_index) = update_stmt.dst.stmt_index.as_ref() else {
                            continue;
                        };
                        if dst_index.get_uniq() != index.get_uniq() {
                            continue;
                        }
                        let fields = update_stmt.dst.fields.as_slice();
                        let mut update_sub_list: Vec<&[FieldKey]> =
                            fields.split(|f| f == &FieldKey::Pointer).collect();
                        update_sub_list.remove(0); // remove pointer key at the beginning
                        let remain_sub_list = &sub_list[i..];
                        // adjust to update fields.
                        // all update fields are fields for a pointer,
                        // but the sub_list can be to any fields, including primitive types and structure.
                        // crate::log!(trace, "remain: {:?}", remain_sub_list);
                        // crate::log!(trace, "update: {:?}", update_sub_list);
                        if remain_sub_list.is_empty()
                            || update_sub_list.starts_with(remain_sub_list)
                        {
                            for update_fields in &update_sub_list[remain_sub_list.len()..] {
                                if update_fields.is_empty() {
                                    continue;
                                }
                                if suffix_fields.as_slice().starts_with(update_fields) {
                                    suffix_fields = suffix_fields.split_off(update_fields.len());
                                } else {
                                    // crate::log_trace!("suffix is not match, suffix is {suffix_fields:?}, buf update fields is: {update_fields:?}");
                                    return None;
                                }
                            }
                            // crate::log!(trace, "update suffix field: {suffix_fields:?}");
                            index = &update_stmt.src;
                            break 'loop_sub;
                        }
                    }

                    // crate::log_trace!("can't find any match update");
                    return None;
                }
                _ => {}
            }
            return None;
        }
        // prefix is used for type refining
        // it is a prefix for strcture instead of location for function.
        if !prefix.is_empty() {
            let suffix = std::mem::replace(&mut suffix_fields, prefix.list.clone());
            suffix_fields.extend(suffix);
        }
        // check if fields exists
        if let FuzzStmt::Load(load) = &program.stmts[index.get()].stmt {
            if let Err(err) = load.state.get_child_by_fields(suffix_fields.as_slice()) {
                if matches!(
                    err,
                    crate::HopperError::UnionErr | crate::HopperError::IndexNotExist
                ) {
                    return None;
                } else {
                    crate::log!(error, "index: {}", index.get());
                    crate::log!(error, "load: {:?}", load.serialize().unwrap());
                    crate::log!(error, "list: {:?} fields: {suffix_fields:?}", self.list);
                    crate::log!(error, "program: {}", program.serialize_all().unwrap());
                    unreachable!("err: {}", err);
                }
            }
        } else if !suffix_fields.is_empty() {
            return None;
        }
        let loc = Location::new(index.use_index(), LocFields::new(suffix_fields));
        Some(loc)
    }

    pub fn from_rule(fields_str: &str) -> eyre::Result<Self> {
        let mut fields = vec![];
        if fields_str.is_empty() {
            return Ok(Self::default());
        }
        let fields_vec = fields_str.split(FIELD_SEP);
        for f in fields_vec {
            if f.is_empty() {
                continue;
            }
            if let Some(rest) = f.strip_prefix('@') {
                fields.push(FieldKey::Root(rest.to_string()));
            } else if f == "&" {
                fields.push(FieldKey::Pointer);
            } else if f == "?" {
                fields.push(FieldKey::Option);
            } else if let Some(rest) = f.strip_prefix('$') {
                let index: usize = rest.parse()?;
                fields.push(index.into());
            } else {
                fields.push(f.trim_end_matches(&[')', ']']).to_string().into());
            }
        }
        Ok(Self { list: fields })
    }
}

impl ObjectSerialize for LocFields {
    fn serialize_obj(&self, _state: &ObjectState) -> eyre::Result<String> {
        self.serialize()
    }
}

impl Deserialize for FieldKey {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        let c = de.peek_char().ok_or_else(|| eyre::eyre!("has char"))?;
        let key = if c == '@' {
            let _ = de.next_char();
            let ident = de.parse_string()?;
            FieldKey::Root(ident)
        } else if c == '&' {
            let _ = de.next_char();
            FieldKey::Pointer
        } else if c == '?' {
            let _ = de.next_char();
            FieldKey::Option
        } else if c == '$' {
            let _ = de.next_char();
            let index: usize = de.parse_number()?;
            index.into()
        } else {
            de.parse_string()?.into()
        };
        Ok(key)
    }
}

impl Deserialize for LocFields {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        de.eat_token("[")?;
        let fields_str = de.next_token_until("]")?;
        Self::from_rule(fields_str)
    }
}

impl ObjectDeserialize for LocFields {
    fn deserialize_obj(de: &mut Deserializer, _state: &mut ObjectState) -> eyre::Result<Self> {
        Self::deserialize(de)
    }
}

macro_rules! impl_location {
    ($ty:ident, $index_ty:ident) => {
        impl CloneProgram for $ty {
            fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
                Self {
                    stmt_index: self.stmt_index.clone_with_program(program),
                    fields: self.fields.clone(),
                }
            }
        }

        impl Serialize for $ty {
            fn serialize(&self) -> eyre::Result<String> {
                if let Some(stmt_index) = &self.stmt_index {
                    Ok(format!(
                        "{}{}",
                        stmt_index.serialize()?,
                        self.fields.serialize()?
                    ))
                } else {
                    self.fields.serialize()
                }
            }
        }

        impl ObjectTranslate for $ty {
            fn translate_obj_to_c(
                &self,
                _state: &ObjectState,
                program: &FuzzProgram,
            ) -> eyre::Result<String> {
                if self.is_null() {
                    return Ok("NULL".to_string());
                }
                let index = self.get_index()?.get();
                let value_name = format!("v{}", index);
                let mut fields = String::new();
                let mut prev_ptr = false;
                for f in self.fields.list.iter() {
                    match f {
                        FieldKey::Index(i) => {
                            fields.push('[');
                            fields.push_str(&i.to_string());
                            fields.push(']');
                            prev_ptr = false;
                        }
                        FieldKey::Field(f) => {
                            if prev_ptr {
                                fields.push_str("->");
                            } else {
                                fields.push('.');
                            }
                            fields.push_str(f);
                            prev_ptr = false;
                        }
                        FieldKey::Pointer => {
                            prev_ptr = true;
                        }
                        _ => {
                            prev_ptr = false;
                        }
                    };
                }
                // if it is point to vec
                let mut is_vec = false;
                if self.fields.is_empty() {
                    if let FuzzStmt::Load(load) = &program.stmts[index].stmt {
                        if crate::utils::is_vec_type(&load.value.type_name()) {
                            is_vec = true;
                        }
                    }
                }
                // if last field is pointer used in right side
                // we should wrap with *({}) for pointer
                // if it is used in left side (e.g update's location),
                // we should ignore it
                if is_vec || prev_ptr {
                    Ok(format!("{}{}", value_name, fields))
                } else if fields.is_empty() {
                    Ok(format!("&{}", value_name))
                } else {
                    Ok(format!("&({}{})", value_name, fields))
                }
            }
        }

        impl ObjectSerialize for $ty {
            fn serialize_obj(&self, _state: &ObjectState) -> eyre::Result<String> {
                self.serialize()
            }
        }

        impl ObjectDeserialize for $ty {
            fn deserialize_obj(
                de: &mut Deserializer,
                _state: &mut ObjectState,
            ) -> eyre::Result<Self> {
                Self::deserialize(de)
            }
        }
    };
}

impl_location!(Location, StmtIndex);
impl_location!(WeakLocation, WeakStmtIndex);

impl Serialize for Option<&Location> {
    fn serialize(&self) -> eyre::Result<String> {
        if let Some(loc) = self {
            loc.serialize()
        } else {
            Ok("null".to_string())
        }
    }
}

impl Deserialize for Location {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        if de.peek_char() == Some('<') {
            let stmt_index = StmtIndex::deserialize(de)?;
            let fields = LocFields::deserialize(de)?;
            Ok(Self::new(stmt_index, fields))
        } else {
            let mut loc = Location::null();
            loc.fields = LocFields::deserialize(de)?;
            Ok(loc)
        }
    }
}

impl Deserialize for WeakLocation {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        let loc = Location::deserialize(de)?;
        Ok(loc.to_weak_loc())
    }
}

impl std::hash::Hash for Location {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.stmt_index.as_ref().map(|i| i.get_uniq()).hash(state);
        self.fields.hash(state);
    }
}

impl fmt::Display for LocFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.serialize().unwrap())
    }
}
