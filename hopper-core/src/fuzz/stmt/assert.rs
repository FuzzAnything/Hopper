use std::cell::RefCell;

use eyre::ContextCompat;

use super::*;

impl WeightedItem for AssertStmt {}

impl StmtMutate for AssertStmt {}

// Assertions that will adding under specific conditions, e.g for specific function invoking.
#[derive(Debug)]
pub struct Assertion {
    pub f_name: String,
    pub arg_pos: Option<usize>,
    pub expected: ExpectedValue,
    pub is_eq: bool,
}

#[derive(Debug)]
pub enum ExpectedValue {
    Load {
        value: FuzzObject,
        state: ObjectState,
    },
    // TODO:
    // Call { arg_pos: Option<usize> },
}

unsafe impl Sync for ExpectedValue {}

thread_local! {
    static ASSERTIONS: RefCell<Vec<Assertion>> = RefCell::new(vec![]);
}

pub fn add_assertion(assertion: Assertion) {
    ASSERTIONS.with(|asserts| {
        crate::log!(info, "add assertion: {assertion:?}");
        asserts.borrow_mut().push(assertion);
    })
}

impl Assertion {
    pub fn assert_call_ret_and_constant(
        f_name: &str,
        value: FuzzObject,
        state: ObjectState,
        is_eq: bool,
    ) -> Self {
        Self {
            f_name: f_name.to_string(),
            arg_pos: None,
            expected: ExpectedValue::Load { value, state },
            is_eq,
        }
    }
}

pub fn parse_assertion(de: &mut crate::Deserializer) -> eyre::Result<Assertion> {
    let f_name = de.next_token_until(" ")?;
    let rule = de.next_token_until(" ")?;
    let is_eq = match rule {
        "==" => true,
        "!=" => false,
        _ => {
            eyre::bail!("unknown operation for assertion: {rule}")
        }
    };
    let g = global_gadgets::get_instance();
    let ty = g
        .get_func_gadget(f_name)?
        .ret_type
        .context("should have ret type")?;
    let mut state = crate::ObjectState::root(format!("expected_{f_name}"), ty);
    let _ = state.replace_weight(0);
    let expected = g.get_object_builder(ty)?.deserialize(de, &mut state)?;
    Ok(crate::fuzz::stmt::Assertion::assert_call_ret_and_constant(
        f_name, expected, state, is_eq,
    ))
}

impl FuzzProgram {
    pub fn insert_required_assertions(&mut self) -> eyre::Result<()> {
        if ASSERTIONS.with(|asserts| asserts.borrow().is_empty()) {
            return Ok(());
        }
        for i in (0..self.stmts.len()).rev() {
            let is = &self.stmts[i];
            if let FuzzStmt::Call(call) = &is.stmt {
                let found = ASSERTIONS.with(|asserts| {
                    let asserts = asserts.borrow();
                    // only support one assertion for each function
                    if let Some(found) = asserts
                        .iter()
                        .find(|assert| assert.f_name == call.fg.f_name)
                    {
                        let check_stmt = if found.arg_pos.is_none() {
                            &is.index
                        } else {
                            // TODO: able to assert arguments
                            return None;
                        };
                        if find_any_assertion(check_stmt, &self.stmts[check_stmt.get()..]) {
                            return None;
                        }
                        let expected = match &found.expected {
                            ExpectedValue::Load { value, state } => {
                                LoadStmt::new_const(value.clone(), state.clone_without_mutate_info(None))
                            }
                        };
                        return Some((found.is_eq, check_stmt.use_index(), expected));
                    }
                    None
                });
                if let Some((is_eq, check_stmt, expected)) = found {
                    let expected_index = self.insert_stmt(i + 1, expected);
                    let assert_stmt = if is_eq {
                        AssertStmt::assert_eq(check_stmt, expected_index)
                    } else {
                        AssertStmt::assert_neq(check_stmt, expected_index)
                    };
                    crate::log!(trace, "add assertion: {}", assert_stmt.serialize()?);
                    let _ = self.insert_stmt(i + 2, assert_stmt);
                }
            }
        }
        Ok(())
    }
}

fn find_any_assertion(target: &StmtIndex, stmts: &[IndexedStmt]) -> bool {
    for is in stmts {
        if let FuzzStmt::Assert(assert) = &is.stmt {
            if let Some(existing) = assert.get_stmt() {
                if existing.get_uniq() == target.get_uniq() {
                    return true;
                }
            }
        }
    }
    false
}

#[test]
fn test_parse_and_gen_assertion() {
    // parse
    let a = parse_assertion(&mut crate::Deserializer::new("test_one == 1", None)).unwrap();
    println!("a: {a:?}");
    assert!(a.is_eq);
    add_assertion(a);
    let a = parse_assertion(&mut crate::Deserializer::new("test_non_zero != 1", None)).unwrap();
    println!("a: {a:?}");
    assert!(!a.is_eq);
    add_assertion(a);

    // gen
    let program = FuzzProgram::generate_program_for_func("test_one").unwrap();
    println!("program: {}", program.serialize().unwrap());
    assert!(matches!(
        program.stmts.last().unwrap().stmt,
        FuzzStmt::Assert(..)
    ));
    let program = FuzzProgram::generate_program_for_func("test_non_zero").unwrap();
    println!("program: {}", program.serialize().unwrap());
    assert!(matches!(
        program.stmts.last().unwrap().stmt,
        FuzzStmt::Assert(..)
    ));
}
