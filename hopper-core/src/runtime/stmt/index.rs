//! Index of statements

use std::{
    cell::Cell,
    fmt,
    rc::{Rc, Weak},
};

use eyre::ContextCompat;

use crate::runtime::*;

/// Index with reference counting
pub trait RcIndex {
    /// Get the index
    fn get(&self) -> usize;
    /// Get its unique ID
    fn get_uniq(&self) -> u64;
    /// Get reference counting
    fn get_ref_used(&self) -> usize;
}

/// Index of statements
#[derive(Debug, Clone)]
pub struct StmtIndex(Rc<Cell<(usize, u64)>>);

/// non-owning reference pointer for StmtIndex
#[derive(Debug, Clone)]
pub struct WeakStmtIndex(Weak<Cell<(usize, u64)>>);

impl RcIndex for StmtIndex {
    fn get(&self) -> usize {
        self.0.get().0
    }
    fn get_uniq(&self) -> u64 {
        self.0.get().1
    }
    fn get_ref_used(&self) -> usize {
        Rc::strong_count(&self.0)
    }
}

impl RcIndex for WeakStmtIndex {
    fn get(&self) -> usize {
        let holder = self.0.upgrade().unwrap();
        holder.get().0
    }
    fn get_uniq(&self) -> u64 {
        let holder = self.0.upgrade().unwrap();
        holder.get().1
    }
    fn get_ref_used(&self) -> usize {
        self.0.strong_count()
    }
}

impl StmtIndex {
    pub fn new(index: usize) -> Self {
        let uniq: u64 = crate::fuzz::gen();
        Self(Rc::new(Cell::new((index, uniq))))
    }

    pub fn dup(&self) -> Self {
        Self(Rc::new(Cell::new((self.get(), self.get_uniq()))))
    }

    /// Update the index with new value
    pub fn set(&self, index: usize) {
        let mut val = self.0.get();
        val.0 = index;
        self.0.replace(val);
    }

    /// Update the uniq with new value
    pub fn set_uniq(&mut self, uniq: u64) {
        let mut val = self.0.get();
        val.1 = uniq;
        self.0.replace(val);
    }

    /// Reset uniq
    pub fn reset_uniq(&mut self) {
        let uniq: u64 = crate::fuzz::gen();
        self.set_uniq(uniq);
    }

    /// Pass the index to other statment
    /// thus we can counting how many statement using it,
    /// or mutate the index from its original place.
    pub fn use_index(&self) -> StmtIndex {
        // clone rc
        Self(self.0.clone())
    }

    /// Downgrade to WeakStmtIndex
    pub fn downgrade(&self) -> WeakStmtIndex {
        WeakStmtIndex(Rc::downgrade(&self.0))
    }

    /// Get value at the index of statement list
    pub fn get_stmt_value<'b>(&self, stmts: &'b [IndexedStmt]) -> Option<&'b FuzzObject> {
        let index = self.get();
        if let Some(indexed_stmt) = stmts.get(index) {
            return indexed_stmt.stmt.get_value();
        }
        None
    }

    /// Get type of statment at the index of statement list
    pub fn get_stmt_type(&self, stmts: &[IndexedStmt]) -> Option<&'static str> {
        let index = self.get();
        if let Some(indexed_stmt) = stmts.get(index) {
            let ty = indexed_stmt.stmt.get_type();
            return Some(ty);
        }
        None
    }
}

impl WeakStmtIndex {
    pub fn upgrade(&self) -> eyre::Result<StmtIndex> {
        let inner = self.0.upgrade().context("can upgrade")?;
        Ok(StmtIndex(inner))
    }

    pub fn is_released(&self) -> bool {
        self.0.strong_count() == 0
    }
}

macro_rules! impl_stmt_index {
    ($ty:ident) => {
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "<{}>", self.get())
            }
        }
        impl PartialEq for $ty {
            fn eq(&self, other: &Self) -> bool {
                self.get() == other.get() && self.get_uniq() == other.get_uniq()
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

impl Serialize for StmtIndex {
    fn serialize(&self) -> eyre::Result<String> {
        Ok(format!("<{}>", self.get()))
    }
}

impl Serialize for WeakStmtIndex {
    fn serialize(&self) -> eyre::Result<String> {
        eyre::ensure!(!self.is_released(), "fail to serialize released index");
        Ok(format!("<{}>", self.get()))
    }
}

impl_stmt_index!(StmtIndex);
impl_stmt_index!(WeakStmtIndex);

impl CloneProgram for Option<StmtIndex> {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        self.as_ref().map(|v| v.clone_with_program(program))
    }
}

impl CloneProgram for Option<WeakStmtIndex> {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        if let Some(index) = self.as_ref() {
            if index.is_released() {
                return None;
            }
            return Some(index.clone_with_program(program));
        }
        None
    }
}

impl CloneProgram for StmtIndex {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        // if index is in program
        if let Some(is) = program.get_stmt_by_index_uniq(self) {
            return is.index.use_index();
        }
        // if index is in tmp_indices
        let index_uniq = self.get_uniq();
        let index = program
            .tmp_indices
            .iter()
            .find(|i| i.get_uniq() == index_uniq);
        if let Some(stmt_index) = index {
            return stmt_index.use_index();
        }
        // create new one
        let stmt_index = self.dup();
        program.tmp_indices.push(stmt_index.use_index());
        stmt_index
    }
}

impl CloneProgram for WeakStmtIndex {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        self.upgrade()
            .unwrap()
            .clone_with_program(program)
            .downgrade()
    }
}

impl Deserialize for StmtIndex {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        de.eat_token("<")?;
        let index: usize = de.parse_next_until(">")?;
        let p = de.program.as_mut().context("deserializer need program")?;
        if index < p.stmts.len() {
            let stmt = p.stmts.get(index).ok_or_else(|| {
                eyre::eyre!("stmt index `{}` is out of bound `{}`", index, p.stmts.len())
            })?;
            let use_index = stmt.index.use_index();
            eyre::ensure!(
                use_index.get() == index,
                "want index {}, but get  {:?}",
                index,
                stmt
            );
            Ok(use_index)
        } else if let Some(stmt_index) = p.tmp_indices.iter().find(|i| i.get() == index) {
            Ok(stmt_index.use_index())
        } else {
            let stmt_index = StmtIndex::new(index);
            p.tmp_indices.push(stmt_index.use_index());
            Ok(stmt_index)
        }
    }
}

impl Deserialize for WeakStmtIndex {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        let index = StmtIndex::deserialize(de)?;
        Ok(index.downgrade())
    }
}

#[test]
fn test_check_used() {
    let index = StmtIndex::new(1);
    assert!(index.get_ref_used() == 1);
    let index2 = index.use_index();
    assert!(index.get_ref_used() == 2);
    assert!(index2.get_ref_used() == 2);
}
