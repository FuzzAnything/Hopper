mod assert;
mod call;
mod file;
mod index;
mod load;
mod update;

pub use assert::*;
pub use call::*;
pub use file::*;
pub use index::*;
pub use load::*;
pub use update::*;

use crate::{feedback::ResourceStates, runtime::*, CloneProgram};

/// Statements for fuzzing program
///
#[derive(Debug)]
pub enum FuzzStmt {
    /// Variable
    Load(Box<LoadStmt>),
    /// Function call
    Call(Box<CallStmt>),
    /// Assert
    Assert(Box<AssertStmt>),
    /// Crate a File
    File(Box<FileStmt>),
    /// Update return value
    Update(Box<UpdateStmt>),
    /// Stub, do nothing
    Stub,
}

/// Define struct that can be viewed as statament
pub trait StmtView: Into<FuzzStmt> + CloneProgram {
    /// Keyword for serde
    const KEYWORD: &'static str;
    /// Get its value
    fn get_value(&self) -> Option<&FuzzObject> {
        None
    }
    /// Evaluate this statement
    fn eval(
        &mut self,
        _used_stmts: &mut [IndexedStmt],
        _resource_states: &mut ResourceStates,
    ) -> eyre::Result<()> {
        // do nothing
        Ok(())
    }
    /// Get its type
    fn get_type(&self) -> &'static str {
        Self::KEYWORD
    }
}

/// Statement with index
#[derive(Debug)]
pub struct IndexedStmt {
    pub index: StmtIndex,
    pub stmt: FuzzStmt,
    pub freed: Option<WeakStmtIndex>,
}

impl IndexedStmt {
    pub fn new(stmt: FuzzStmt, index: usize) -> Self {
        Self {
            index: StmtIndex::new(index),
            stmt,
            freed: None,
        }
    }
}

impl CloneProgram for IndexedStmt {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        Self {
            index: self.index.clone_with_program(program),
            stmt: self.stmt.clone_with_program(program),
            freed: self.freed.clone_with_program(program),
        }
    }
}

impl Serialize for IndexedStmt {
    fn serialize(&self) -> eyre::Result<String> {
        let mut out = String::new();
        out.push_str(&self.index.serialize()?);
        out.push(' ');
        if let Some(i) = &self.freed {
            out.push('~');
            out.push_str(&i.serialize()?);
            out.push(' ');
        }
        out.push_str(&self.stmt.serialize()?);
        out.push('\n');
        Ok(out)
    }
}

impl Deserialize for IndexedStmt {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        let stmt_index = StmtIndex::deserialize(de)?;
        let mut freed = None;
        if de.strip_token("~") {
            let index = WeakStmtIndex::deserialize(de)?;
            freed = Some(index);
        }
        let stmt = FuzzStmt::deserialize(de)?;
        let is = IndexedStmt {
            index: stmt_index,
            stmt,
            freed,
        };
        Ok(is)
    }
}

#[macro_export]
macro_rules! impl_stmt_match {
    (@inner, $name:ident, $f:ident, $($ty:ident),* ) => {
        match $name {
            $( FuzzStmt::$ty(inner) => inner.$f(), )*
            _ => { unreachable!() }
        }
    };
    (@inner, $name:ident, $f:ident($arg1:ident), $($ty:ident),* ) => {
        match $name {
            $( FuzzStmt::$ty(inner) => inner.$f($arg1), )*
            _ => { unreachable!() }
        }
    };
    (@inner, $name:ident, $f:ident($arg1:ident).into(), $($ty:ident),* ) => {
        match $name {
            $( FuzzStmt::$ty(inner) => inner.$f($arg1).into(), )*
            _ => { unreachable!() }
        }
    };
    (@inner, $name:ident, $f:ident($arg1:ident, $arg2:ident), $($ty:ident),* ) => {
        match $name {
            $( FuzzStmt::$ty(inner) => inner.$f($arg1, $arg2), )*
            _ => { unreachable!() }
        }
    };
    (@inner, $name:ident, $f:ident($arg1:ident, $arg2:ident, $arg3:ident), $($ty:ident),* ) => {
        match $name {
            $( FuzzStmt::$ty(inner) => inner.$f($arg1, $arg2, $arg3), )*
            _ => { unreachable!() }
        }
    };
    (@inner, $name:ident, $f:ident($arg1:ident, $arg2:ident, $arg3:ident, $arg4:ident), $($ty:ident),* ) => {
        match $name {
            $( FuzzStmt::$ty(inner) => inner.$f($arg1, $arg2, $arg3, $arg4), )*
            _ => { unreachable!() }
        }
    };
    ($($t:tt)*) => {
        impl_stmt_match!(@inner, $($t)*, Load, Update, Call, Assert, File)
    };
}

impl FuzzStmt {
    pub fn eval(
        &mut self,
        used_stmts: &mut [IndexedStmt],
        resource_states: &mut ResourceStates,
    ) -> eyre::Result<()> {
        impl_stmt_match!(self, eval(used_stmts, resource_states))
    }

    pub fn get_value(&self) -> Option<&FuzzObject> {
        impl_stmt_match!(self, get_value)
    }

    pub fn get_type(&self) -> &'static str {
        impl_stmt_match!(self, get_type)
    }

    /// Replace itself with stub stmt
    pub fn lend(&mut self) -> FuzzStmt {
        let stub = FuzzStmt::Stub;
        std::mem::replace(self, stub)
    }

    /// Withdraw statement
    pub fn withdraw(&mut self, stmt: FuzzStmt) {
        let _ = std::mem::replace(self, stmt);
    }

    pub fn is_stub(&self) -> bool {
        matches!(self, FuzzStmt::Stub)
    }

    pub fn is_load(&self) -> bool {
        matches!(self, Self::Load(_))
    }

    pub fn is_call(&self) -> bool {
        matches!(self, Self::Call(_))
    }
}

impl CloneProgram for FuzzStmt {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        if matches!(self, FuzzStmt::Stub) {
            return FuzzStmt::Stub;
        }
        impl_stmt_match!(self, clone_with_program(program).into())
    }
}

impl Serialize for FuzzStmt {
    fn serialize(&self) -> eyre::Result<String> {
        if self.is_stub() {
            return Ok("stub".to_string());
        }
        impl_stmt_match!(self, serialize)
    }
}

impl Deserialize for FuzzStmt {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        let stmt_type = de.next_token_until(" ")?;
        let stmt = match stmt_type {
            LoadStmt::KEYWORD => LoadStmt::deserialize(de)?.into(),
            UpdateStmt::KEYWORD => UpdateStmt::deserialize(de)?.into(),
            CallStmt::KEYWORD => CallStmt::deserialize(de)?.into(),
            AssertStmt::KEYWORD => AssertStmt::deserialize(de)?.into(),
            FileStmt::KEYWORD => FileStmt::deserialize(de)?.into(),
            _ => eyre::bail!("Unknow statement type: `{}`", stmt_type),
        };
        Ok(stmt)
    }
}
