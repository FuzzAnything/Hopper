//! State of object in load statement,
//! it stores state information for mutating, serde..

use std::{cell::RefCell, ptr::NonNull, rc::Rc};

use eyre::ContextCompat;

use crate::{
    feedback::{CmpBuf, CmpState},
    fuzz::{MutateOperation, MutateOperator},
    CloneProgram, FieldEqual, FieldKey, FuzzProgram, HopperError, LocFields, Location, StmtIndex,
};

#[derive(Debug)]
pub struct ObjectState {
    // -- tree struct of the state --
    /// key
    pub key: FieldKey,
    /// parent
    pub parent: Option<NonNull<ObjectState>>,
    /// children
    pub children: Vec<Box<ObjectState>>,
    // -- data the state holds --
    /// info used for mutation
    pub mutate: Rc<RefCell<MutateState>>,
    /// info used for pointer
    pub pointer: Option<PointerState>,
    // -- info about the object underneath --
    /// if the object is an union
    pub is_union: bool,
    /// ty
    pub ty: &'static str,
}

// Check fields to support both &a[0] and &a
#[inline]
pub fn check_fields<'a>(fields: &'a [FieldKey], state: &ObjectState) -> &'a [FieldKey] {
    if !fields.is_empty()
        && fields.first() == Some(&FieldKey::Index(0))
        && state
            .children
            .first()
            .map_or(true, |c| c.key != FieldKey::Index(0))
    {
        return &fields[1..];
    }
    fields
}

macro_rules! error_handle_get_field {
    ($state: ident, $key: ident) => {{
        // crate::log!(warn, "fail to find: {fields:?} in {:?}", self);
        let field = $key.as_field_key();
        if let FieldKey::Index(i) = field {
            if let Some(c) = $state.children.first() {
                if matches!(c.key, FieldKey::Index(_)) && i >= $state.children.len() {
                    return Err(HopperError::IndexNotExist);
                }
            } else {
                return Err(HopperError::IndexNotExist);
            }
        }
        if $state.is_union {
            return Err(HopperError::UnionErr);
        }
        return Err(HopperError::FieldNotFound(format!(
            "fail to find child `{:?}` in `{:?}`, child: {:?}",
            $key,
            $state.key,
            $state
                .children
                .iter()
                .map(|c| &c.key)
                .collect::<Vec::<&FieldKey>>()
        )));
    }};
}

impl ObjectState {
    pub fn root<T: ToString>(ident: T, ty: &'static str) -> Self {
        let s = Self {
            key: FieldKey::Root(ident.to_string()),
            parent: None,
            children: vec![],
            mutate: Rc::new(RefCell::new(MutateState::default())),
            pointer: None,
            is_union: false,
            ty,
        };
        if s.is_private_field() {
            s.mutate.borrow_mut().set_weight(0);
        }
        s
    }

    /// Create child's state, which located by `key`
    pub fn add_child<K: Into<FieldKey>>(&mut self, key: K, ty: &'static str) -> &mut Self {
        let child = Box::new(Self {
            key: key.into(),
            parent: NonNull::new(self),
            children: vec![],
            mutate: Rc::new(RefCell::new(MutateState::default())),
            pointer: None,
            is_union: false,
            ty,
        });
        if child.is_private_field() || self.is_private_field() {
            child.mutate.borrow_mut().set_weight(0);
        }
        // crate::log!(trace, "add child {:?}", child.key);
        self.children.push(child);
        self
    }

    pub fn add_child_at_offset(&mut self, offset: usize, ty: &'static str) -> &mut Self {
        let child = Box::new(Self {
            key: offset.into(),
            parent: NonNull::new(self),
            children: vec![],
            mutate: Rc::new(RefCell::new(MutateState::default())),
            pointer: None,
            is_union: false,
            ty,
        });
        if self.is_private_field() {
            child.mutate.borrow_mut().set_weight(0);
        }
        self.children.insert(offset, child);
        self
    }

    pub fn resort_children_indices(&mut self) {
        for index in 0..self.children.len() {
            if !self.children[index].key.is_index() {
                break;
            }
            self.children[index].key = index.into();
        }
    }

    pub fn clear(&mut self) {
        self.children.clear();
    }

    pub fn set_ident<T: ToString>(&mut self, ident: T) {
        self.key = FieldKey::Root(ident.to_string());
    }

    /// Get its parent
    pub fn get_parent(&self) -> Option<&ObjectState> {
        self.parent.map(|p| unsafe { p.as_ref() })
    }

    /// Check if current field is private or not
    /// private field's ident is starts with '_'
    pub fn is_private_field(&self) -> bool {
        match &self.key {
            FieldKey::Root(ident) => {
                if ident.starts_with('_') {
                    return true;
                }
            }
            FieldKey::Field(ident) => {
                if ident.starts_with('_') {
                    return true;
                }
            }
            _ => {
                if let Some(p) = self.get_parent() {
                    if p.is_private_field() {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Get last reference of child's state
    /// used in union's serialzie
    pub fn last_child(&self) -> eyre::Result<&ObjectState> {
        self.children
            .last()
            .context("fail to get last child")
            .map(|v| v.as_ref())
    }

    /// Get last mut reference of child's state
    /// used in generation and de-ser
    pub fn last_child_mut(&mut self) -> eyre::Result<&mut ObjectState> {
        self.children
            .last_mut()
            .context("fail to get last child")
            .map(|v| v.as_mut())
    }

    /// Get reference of child's state by key
    /// use in struct's serialize
    pub fn get_child<F: FieldEqual + std::fmt::Debug>(
        &self,
        key: F,
    ) -> Result<&ObjectState, HopperError> {
        let ret = self.children.iter().find(|c| key.eq_field(&c.key));
        if ret.is_none() {
            error_handle_get_field!(self, key);
        };
        Ok(ret.unwrap())
    }

    /// Get mut reference of child's state by key
    /// use in mutation
    pub fn get_child_mut<F: FieldEqual + std::fmt::Debug>(
        &mut self,
        key: F,
    ) -> Result<&mut ObjectState, HopperError> {
        let ret = self.children.iter().position(|c| key.eq_field(&c.key));
        if let Some(index) = ret {
            Ok(&mut self.children[index])
        } else {
            error_handle_get_field!(self, key);
        }
    }

    /// Get reference of child's state by keys recursively
    pub fn get_child_by_fields(&self, fields: &[FieldKey]) -> Result<&ObjectState, HopperError> {
        let fields = check_fields(fields, self);
        if fields.is_empty() {
            return Ok(self);
        }
        let state = self.get_child(&fields[0])?;
        state.get_child_by_fields(&fields[1..])
    }

    /// Get reference of child's mut state by keys recursively
    pub fn get_child_mut_by_fields(
        &mut self,
        fields: &[FieldKey],
    ) -> Result<&mut ObjectState, HopperError> {
        let fields = check_fields(fields, self);
        if fields.is_empty() {
            return Ok(self);
        }
        let state = self.get_child_mut(&fields[0])?;
        state.get_child_mut_by_fields(&fields[1..])
    }

    /// Get full path of the state
    pub fn get_location_fields(&self) -> LocFields {
        let mut fields = vec![];
        let mut st = self;
        fields.push(st.key.clone());
        while let Some(p) = st.get_parent() {
            fields.push(p.key.clone());
            st = p;
        }
        // remove root
        fields.pop();
        fields.reverse();
        LocFields::new(fields)
    }

    /// Get pointer
    pub fn get_pointer(&self) -> eyre::Result<&PointerState> {
        self.pointer
            .as_ref()
            .ok_or_else(|| eyre::eyre!("pointer has pointer state"))
    }

    /// Get pointer mut
    pub fn get_pointer_mut(&mut self) -> eyre::Result<&mut PointerState> {
        self.pointer
            .as_mut()
            .ok_or_else(|| eyre::eyre!("pointer has pointer state"))
    }

    // Get pointer statement
    pub fn get_pointer_stmt_index(&self) -> Option<&StmtIndex> {
        if let Some(ps) = &self.pointer {
            return ps.pointer_location.stmt_index.as_ref();
        }
        None
    }

    /// Return mutate operator for current state
    /// which used after mutation, and also increase the count of mutation
    pub fn as_mutate_operator(&self, op: MutateOperation) -> MutateOperator {
        let fields = self.inc_mutation().get_location_fields();
        let mut loc = Location::null();
        loc.fields = fields;
        MutateOperator::new(loc, op)
    }

    /// Inc(+1) mutations
    pub fn inc_mutation(&self) -> &Self {
        self.mutate.borrow_mut().inc_mutation();
        /*
        let mut st = self;
        while let Some(p) = st.get_parent() {
            st = p;
            (&st.mutate).borrow_mut().inc_mutation();
        }
        */
        self
    }

    /// Get child's position whose state with deterministic flag
    pub fn get_deterministic_child_position(&self) -> Option<usize> {
        self.children.iter().position(|s| s.is_deterministic())
    }

    /// if it is deterministic or not
    pub fn is_deterministic(&self) -> bool {
        self.mutate.borrow().deterministic
    }

    /// Mark current state no-deterministic , and check its parent's state,
    /// If all the children is no-deterministic, the parent become no-deter too.
    pub fn done_deterministic(&self) {
        crate::log!(trace, "{:?} done det", self.key);
        self.done_deterministic_itself();
        self.update_parent_deterministic();
    }

    /// Check parent's state of deterministic
    pub fn update_parent_deterministic(&self) {
        let mut st = self;
        while let Some(p) = st.get_parent() {
            // parent may be vec/array/struct,
            // we only propagate if parent is struct,
            // since array/vec has det steps.
            if let FieldKey::Field(_) = st.key {
                st = p;
                if st.get_deterministic_child_position().is_none() {
                    st.done_deterministic_itself();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    /// Mark current state no-deterministic, do not check and modify its parent.
    pub fn done_deterministic_itself(&self) {
        let mut mutate_state = self.mutate.borrow_mut();
        if !mutate_state.deterministic {
            return;
        }
        // crate::log!(trace, "{:?} become det", self.key);
        mutate_state.done_deterministic();
        for c in &self.children {
            c.done_deterministic_itself();
        }
    }

    /// If has any stmt in state's pointee satisfy `filter`
    pub fn find_any_stmt_in_state_with<F: FnMut(&StmtIndex) -> bool>(&self, mut filter: F) -> bool {
        let mut st = vec![self];
        while let Some(s) = st.pop() {
            if let Some(i) = &s.get_pointer_stmt_index() {
                if filter(i) {
                    return true;
                }
            }
            for sub_state in s.children.iter() {
                // only consider first element for sequence
                if sub_state.children.is_empty() {
                    if let FieldKey::Index(_) = sub_state.key {
                        break;
                    }
                }
                st.push(sub_state);
            }
        }
        false
    }

    /// find all locations whose type is `type_name` in the object
    pub fn find_fields_with<F: Fn(&ObjectState) -> bool>(
        &self,
        filter: F,
        partial: bool,
    ) -> Vec<LocFields> {
        let mut found = vec![];
        let mut st = vec![self];
        while let Some(s) = st.pop() {
            if filter(s) {
                found.push(s.get_location_fields());
            }
            for sub_state in s.children.iter() {
                st.push(sub_state);
                // only consider first element for sequence
                if partial || sub_state.children.is_empty() {
                    if let FieldKey::Index(_) = sub_state.key {
                        break;
                    }
                }
            }
        }
        found
    }

    /// Is null or not
    pub fn is_null(&self) -> bool {
        if let FieldKey::Option = self.key {
            return self.pointer.is_none();
        }
        if let Some(ps) = self.pointer.as_ref() {
            return ps.pointer_location.is_null();
        }
        false
    }

    /// Is non-null or not
    pub fn is_non_null(&self) -> bool {
        if let FieldKey::Option = self.key {
            return self.pointer.is_some();
        }
        if let Some(ps) = self.pointer.as_ref() {
            return !ps.pointer_location.is_null();
        }
        false
    }

    /// Show the state as a tree for debugging
    pub fn show_tree(&self, depth: usize) {
        println!(
            "key: {:?}, depth: {}, addr: {:#x}, parent: {:?}, det: {}",
            self.key,
            depth,
            self as *const Self as usize,
            self.parent,
            self.is_deterministic()
        );
        for c in &self.children {
            c.show_tree(depth + 1);
            let parent = c.get_parent().unwrap();
            assert!(parent.key == self.key, "parent is not match: {parent:?}");
        }
    }

    /// Clone state without mutate state
    pub fn clone_without_mutate_info(&self, parent: Option<NonNull<Self>>) -> Box<Self> {
        let mut s = Box::new(Self {
            key: self.key.clone(),
            parent,
            children: vec![],
            mutate: Rc::new(RefCell::new(MutateState::default())),
            pointer: self.pointer.as_ref().map(|s| s.shallow_clone()),
            is_union: self.is_union,
            ty: self.ty,
        });
        s.children = self
            .children
            .iter()
            .map(|c| c.clone_without_mutate_info(NonNull::new(s.as_mut())))
            .collect();
        s
    }

    /// Copy child's state from `from` to `to`
    pub fn dup_child_state(&mut self, from: usize, to: usize) {
        crate::log!(
            trace,
            "copy {from} to {to}, #child: {}",
            self.children[from].children.len()
        );
        debug_assert!(from < self.children.len() || to < self.children.len());
        let parent = NonNull::new(self);
        let mut s = self.children[from].clone_without_mutate_info(parent);
        s.key = to.into();
        if s.is_private_field() {
            s.mutate.borrow_mut().set_weight(0);
        }
        self.children.insert(to, s);
    }
}

#[derive(Debug, Clone)]
pub struct MutateState {
    pub num_mutations: usize,
    pub weight: usize,
    pub deterministic: bool,
    pub det_iter: usize,
    pub related_cmps: Vec<CmpState>,
    pub cmp_bufs: Vec<CmpBuf>,
}

impl Default for MutateState {
    fn default() -> Self {
        Self {
            num_mutations: 0,
            weight: 1,
            deterministic: true,
            det_iter: 0,
            related_cmps: vec![],
            cmp_bufs: vec![],
        }
    }
}

impl MutateState {
    /// Done deterministic step
    pub fn done_deterministic(&mut self) {
        self.deterministic = false;
    }

    /// Count mutation
    pub fn inc_mutation(&mut self) {
        self.num_mutations += 1;
    }

    /// Get mutation
    pub fn get_mutation(&self) -> usize {
        self.num_mutations
    }

    /// Set weight
    pub fn set_weight(&mut self, weight: usize) {
        self.weight = weight;
    }

    /// Get weight
    pub fn get_weight(&self) -> usize {
        self.weight
    }

    /// Is zero weight or not ?
    pub fn is_zero_weight(&self) -> bool {
        self.weight == 0
    }

    /// Mutation on the `loc` affect cmp's value
    pub fn affect_cmp(&mut self, cmp_state: CmpState) {
        // if self.related_cmps.iter_mut().any(|c| c.id == cmp_state.id) {
        //     return;
        // }
        self.related_cmps.push(cmp_state);
        // increase weights
        self.weight = 1 + self
            .related_cmps
            .iter()
            .filter(|c| c.op.borrow().is_solved())
            .count();
        // avoid huge weight
        if self.weight > 5 {
            self.weight = 5;
        }
    }

    /// Mutation on the `loc` affect cmp function
    pub fn affect_cmp_buf(&mut self, cmp_buf: CmpBuf) {
        // if self.cmp_bufs.iter_mut().any(|c| c.id == cmp_buf.id) {
        //     return;
        // }
        self.cmp_bufs.push(cmp_buf);
    }

    /// Move to next deterministic iteration
    pub fn next_det_iter(&mut self) {
        self.det_iter += 1;
    }

    pub fn set_det_iter(&mut self, iter: usize) {
        self.det_iter = iter;
    }
}

#[derive(Debug)]
pub struct PointerState {
    /// Inner type of pointer
    pub pointer_type: &'static str,
    /// Is mut
    pub is_mut: bool,
    /// Location of pointer
    pub pointer_location: Location,
    /// stub for mock sth
    pub stub: bool,
}

impl PointerState {
    /// New state for pointer
    pub fn new_pointer(loc: Location, pointer_type: &'static str, is_mut: bool) -> Self {
        Self {
            pointer_type,
            is_mut,
            pointer_location: loc,
            stub: false,
        }
    }

    /// New state for fn pointer
    pub fn new_fn_pointer(pointer_type: &'static str, is_mut: bool) -> Self {
        Self {
            pointer_type,
            is_mut,
            // fn pointer fill pointer directly, thus it does not need location
            pointer_location: Location::null(),
            stub: false,
        }
    }

    /// Shallow clone, that clone the location directly
    pub fn shallow_clone(&self) -> Self {
        Self {
            pointer_type: self.pointer_type,
            is_mut: self.is_mut,
            pointer_location: self.pointer_location.use_loc(),
            stub: self.stub,
        }
    }
}

impl CloneProgram for Box<ObjectState> {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        let mut new_state = Box::new(ObjectState {
            key: self.key.clone(),
            mutate: self.mutate.clone(),
            pointer: self.pointer.clone_with_program(program),
            parent: self.parent,
            children: vec![],
            is_union: self.is_union,
            ty: self.ty,
        });
        let parent_ptr = NonNull::new(new_state.as_mut());
        for c in self.children.iter() {
            let mut new_c = c.clone_with_program(program);
            new_c.parent = parent_ptr;
            new_state.children.push(new_c);
        }
        new_state
    }
}

impl CloneProgram for Option<PointerState> {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        self.as_ref().map(|ps| PointerState {
            pointer_type: ps.pointer_type,
            is_mut: ps.is_mut,
            pointer_location: ps.pointer_location.clone_with_program(program),
            stub: ps.stub,
        })
    }
}

#[test]
fn test_state_inc() {
    let mut program = FuzzProgram::default();
    let state = Box::new(ObjectState::root("test", ""));
    assert_eq!(state.mutate.borrow().num_mutations, 0);
    let state2 = state.clone_with_program(&mut program);
    state2.inc_mutation();
    assert_eq!(state.mutate.borrow().num_mutations, 1);
}

#[test]
fn test_get_child_and_clone_state() {
    use crate::Serialize;
    let mut program = FuzzProgram::default();
    let state2 = {
        let mut state = Box::new(ObjectState::root("test", ""));
        let sub = state
            .add_child("xx".to_string(), "")
            .last_child_mut()
            .unwrap()
            .add_child("bb".to_string(), "")
            .add_child("cc".to_string(), "")
            .last_child_mut()
            .unwrap();

        let fields = sub.get_location_fields();
        assert_eq!(fields.serialize().unwrap(), "[xx.cc]");
        let mut new_state = state.clone_with_program(&mut program);
        new_state.add_child("dd".to_string(), "");
        state.show_tree(0);
        new_state
    };

    state2.show_tree(0);
    let sub1 = state2.get_child("xx").unwrap();
    assert_eq!(sub1.key, "xx".to_string().into());
    let sub2 = sub1.get_child("bb").unwrap();
    assert_eq!(sub2.key, "bb".to_string().into());
    let sub3 = state2.get_child_by_fields(&[]).unwrap();
    assert_eq!(sub3.key, FieldKey::Root("test".to_string()));
    let sub4 = state2
        .get_child_by_fields(&["xx".to_string().into()])
        .unwrap();
    assert_eq!(sub4.key, "xx".to_string().into());
    let sub5 = state2
        .get_child_by_fields(&["xx".to_string().into(), "bb".to_string().into()])
        .unwrap();
    assert_eq!(sub5.key, "bb".to_string().into());
    sub5.inc_mutation();
    let fields = sub5.get_location_fields();
    assert_eq!(fields.serialize().unwrap(), "[xx.bb]");
}
