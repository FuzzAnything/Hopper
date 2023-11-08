//! Assert statement
//! Used for assert some attributes
//! format: assset target

use eyre::ContextCompat;
use hopper_derive::Serde;

use crate::{feedback::ResourceStates, runtime::*, utils};

#[derive(Debug, Clone, Serde)]
pub enum AssertRule {
    /// Assert nothing
    None,
    /// Check pointer non-null
    NonNull { stmt: WeakStmtIndex },
    /// Initialized
    Initialized {
        stmt: WeakStmtIndex,
        call: WeakStmtIndex,
    },
    Eq {
        stmt: WeakStmtIndex,
        expected: StmtIndex,
    },
    Neq {
        stmt: WeakStmtIndex,
        expected: StmtIndex,
    }
}

#[derive(Debug, Default)]
pub struct AssertStmt {
    pub rule: AssertRule,
}

impl Default for AssertRule {
    fn default() -> Self {
        Self::None
    }
}

impl AssertStmt {
    pub fn assert_non_null(stmt: StmtIndex) -> Self {
        let stmt = stmt.downgrade();
        Self {
            rule: AssertRule::NonNull { stmt },
        }
    }
    pub fn assert_initialized(stmt: StmtIndex, call: StmtIndex) -> Self {
        let stmt = stmt.downgrade();
        let call = call.downgrade();
        Self {
            rule: AssertRule::Initialized { stmt, call },
        }
    }
    pub fn assert_eq(stmt: StmtIndex, expected: StmtIndex) -> Self {
        Self {
            rule: AssertRule::Eq { stmt: stmt.downgrade(), expected },
        }
    }
    pub fn assert_neq(stmt: StmtIndex, expected: StmtIndex) -> Self {
        Self {
            rule: AssertRule::Neq { stmt: stmt.downgrade(), expected },
        }
    }
    pub fn get_stmt(&self) -> Option<&WeakStmtIndex> {
        match &self.rule {
            AssertRule::NonNull { stmt } => Some(stmt),
            AssertRule::Eq { stmt, expected: _ } => Some(stmt),
            AssertRule::Neq { stmt, expected: _ } => Some(stmt),
            _ => None
        }
    }
}

impl StmtView for AssertStmt {
    const KEYWORD: &'static str = "assert";

    fn eval(
        &mut self,
        used_stmts: &mut [IndexedStmt],
        _resource_states: &mut ResourceStates,
    ) -> eyre::Result<()> {
        match &self.rule {
            AssertRule::NonNull { stmt } => {
                let index = stmt.get();
                if let FuzzStmt::Call(call) = &used_stmts[index].stmt {
                    if let Some(val) = &call.ret {
                        let type_name = val.type_name();
                        if utils::is_pointer_type(type_name) {
                            let ptr = val.get_ptr_by_keys(&[FieldKey::Pointer])?;
                            if ptr.is_null() || (ptr as usize) < 0x30_0000usize {
                                eyre::bail!(crate::HopperError::AssertError{
                                    msg: format!(
                                        "assert non-null failure for {} at {index}, return address: {ptr:?}",
                                        call.fg.f_name
                                    ), 
                                    silent: true});
                            }
                        }
                    }
                }
            }
            AssertRule::Initialized { stmt, call: _ } => {
                let index = stmt.get();
                if let FuzzStmt::Load(load) = &used_stmts[index].stmt {
                    let ty = load.state.ty;
                    let ptr = if utils::is_vec_type(ty) {
                        load.value.get_ptr_by_keys(&[FieldKey::Index(0), FieldKey::Pointer])?
                    } else {
                        load.value.get_ptr_by_keys(&[FieldKey::Pointer])?
                    };
                    if ptr.is_null() {
                        eyre::bail!(crate::HopperError::AssertError {
                            msg: format!(
                                "assert initialized failure for {} at {index}",
                                load.value.type_name()
                            ),
                            silent: true
                        });
                    }
                }
            }
            AssertRule::Eq { stmt, expected } => {
                let index = stmt.get();
                let expected = expected.get();
                if let FuzzStmt::Call(call) = &used_stmts[index].stmt {
                    if let Some(val) = &call.ret {
                        let expected_val = match &used_stmts[expected].stmt {
                            FuzzStmt::Call(call) => {
                                call.ret.as_ref().context("call should return value")?
                            }
                            FuzzStmt::Load(load) => &load.value,
                            _ => {
                                eyre::bail!("expected statement should be call or load.")
                            }
                        };
                        eyre::ensure!(
                            val.type_id() == expected_val.type_id(),
                            "the compare values should have the same types"
                        );
                        let val_str = val.serialize()?;
                        let expected_str = expected_val.serialize()?;
                        if val_str != expected_str {
                            eyre::bail!(crate::HopperError::AssertError {
                                msg: format!(
                                    "assert equal but {val_str} != {expected_str}",
                                ),
                                silent: false
                            });
                        }
                    }
                }
            }
            AssertRule::Neq { stmt, expected } => {
                let index = stmt.get();
                let expected = expected.get();
                if let FuzzStmt::Call(call) = &used_stmts[index].stmt {
                    if let Some(val) = &call.ret {
                        let expected_val = match &used_stmts[expected].stmt {
                            FuzzStmt::Call(call) => {
                                call.ret.as_ref().context("call should return value")?
                            }
                            FuzzStmt::Load(load) => &load.value,
                            _ => {
                                eyre::bail!("expected statement should be call or load.")
                            }
                        };
                        eyre::ensure!(
                            val.type_id() == expected_val.type_id(),
                            "the compare values should have the same types"
                        );
                        let val_str = val.serialize()?;
                        let expected_str = expected_val.serialize()?;
                        if val_str == expected_str {
                            eyre::bail!(crate::HopperError::AssertError {
                                msg: format!(
                                    "assert not equal but {val_str} == {expected_str}",
                                ),
                                silent: false
                            });
                        }
                    }
                }
            }
            AssertRule::None => {}
        }
        Ok(())
    }

    fn get_value(&self) -> Option<&FuzzObject> {
        None
    }
}

impl CloneProgram for AssertStmt {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        Self {
            rule: self.rule.clone_with_program(program),
        }
    }
}

impl CloneProgram for AssertRule {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        match self {
            AssertRule::NonNull { stmt } => AssertRule::NonNull {
                stmt: stmt.clone_with_program(program),
            },
            AssertRule::Initialized { stmt, call } => AssertRule::Initialized {
                stmt: stmt.clone_with_program(program),
                call: call.clone_with_program(program),
            },
            AssertRule::Eq { stmt, expected } => AssertRule::Eq {
                stmt: stmt.clone_with_program(program),
                expected: expected.clone_with_program(program),
            },
            AssertRule::Neq { stmt, expected } => AssertRule::Neq {
                stmt: stmt.clone_with_program(program),
                expected: expected.clone_with_program(program),
            },
            _ => self.clone(),
        }
    }
}

impl From<AssertStmt> for FuzzStmt {
    fn from(stmt: AssertStmt) -> Self {
        FuzzStmt::Assert(Box::new(stmt))
    }
}

impl Serialize for AssertStmt {
    fn serialize(&self) -> eyre::Result<String> {
        Ok(format!("{} {}", Self::KEYWORD, self.rule.serialize()?,))
    }
}

impl Deserialize for AssertStmt {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        // de.strip_token(Self::KEYWORD);
        let rule = AssertRule::deserialize(de)?;
        Ok(Self { rule })
    }
}
