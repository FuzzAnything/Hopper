mod constraint;
mod context;
mod entry;
pub mod literal;
mod parse;
mod ret;
mod role;

pub use constraint::*;
pub use context::*;
pub use entry::*;
pub use role::*;

use std::cell::RefCell;
use std::collections::HashMap;

use crate::{config, global_gadgets, log, LocFields, FN_POINTER_PREFIX};

pub const UNION_ROOT: &str = "__UNION";

/// Constriants for mutation
#[derive(Debug, Default)]
pub struct Constraints {
    /// constraints for fucntions
    pub func_constraints: HashMap<String, FuncConstraint>,
    /// Constraints for types (Generic)
    pub type_constraints: HashMap<String, TypeConstraint>,
}

thread_local! {
    pub static CONSTRAINTS: RefCell<Constraints> = RefCell::new(Constraints::default());
}

pub fn init_constraints() -> eyre::Result<bool> {
    log!(info, "init constraint...");
    // load configuration file if it exists
    let constraint_file = config::constraint_file_path();
    CONSTRAINTS.with(|constraints| {
        let mut c = constraints.borrow_mut();
        if constraint_file.exists() {
            c.read_from_config(&constraint_file)?;
            c.read_from_custom()?;
            log!(info, "load constraints from config file");
            return Ok(true);
        }
        c.read_internal_config()?;
        // select functions for inference
        for (f_name, fg) in global_gadgets::get_instance().functions.iter() {
            if config::get_config().match_func(f_name) {
                log!(info, "init constraint for {f_name}");
                c.init_func_constraint(f_name)?;
                // check arguments
                for &arg_type in fg.arg_types {
                    let mut check_type = arg_type;
                    if let Some(inner) = crate::get_pointer_inner(arg_type) {
                        check_type = inner;
                    }
                    if crate::is_custom_type(check_type) {
                        c.init_type_constraint(check_type)?;
                    }
                }
            }
        }
        c.read_from_custom()?;
        Ok(false)
    })
}

pub fn save_constraints_to_file() -> eyre::Result<()> {
    CONSTRAINTS.with(|c| c.borrow().save_to_file(&config::constraint_file_path()))
}

/// Filter function that can be inserted into program
#[inline]
pub fn filter_function(f_name: &str) -> bool {
    CONSTRAINTS.with(|c| {
        c.borrow()
            .get_func_constraint(f_name)
            .map_or(false, |c| c.is_success())
    })
}

#[inline]
pub fn filter_target_function(f_name: &str) -> bool {
    if let Some(target) = config::get_config().func_target {
        if f_name != target {
            return false;
        }
    }
    CONSTRAINTS.with(|c| {
        c.borrow()
            .get_func_constraint(f_name)
            .map_or(false, |c| c.is_success())
    })
}

#[inline]
pub fn filter_fn_pointer(f_name: &str) -> bool {
    f_name.starts_with(FN_POINTER_PREFIX)
}

#[inline]
pub fn filter_function_constraint_with<F: FnOnce(&FuncConstraint) -> bool>(
    f_name: &str,
    filter: F,
) -> bool {
    CONSTRAINTS.with(|c| c.borrow().get_func_constraint(f_name).map_or(false, filter))
}

pub fn filter_function_field_constraint_with<F: FnMut(&Constraint) -> bool>(
    f_name: &str,
    arg_pos: usize,
    fields: &LocFields,
    mut filter: F,
) -> bool {
    filter_function_constraint_with(f_name, |fc| {
        fc.arg_constraints[arg_pos]
            .list
            .iter()
            .any(|tc| &tc.key == fields && filter(&tc.constraint))
    })
}

pub fn inspect_function_constraint_with<T, F: FnMut(&FuncConstraint) -> eyre::Result<T>>(
    f_name: &str,
    mut callback: F,
) -> eyre::Result<T> {
    CONSTRAINTS.with(|c| {
        if let Some(fc) = c.borrow().get_func_constraint(f_name) {
            callback(fc)
        } else {
            log::trace!("fail to find function `{f_name}` in constraint!");
            let fc = FuncConstraint::init(f_name)?;
            callback(&fc)
        }
    })
}

pub fn inspect_function_constraint_mut_with<T, F: FnMut(&mut FuncConstraint) -> eyre::Result<T>>(
    f_name: &str,
    mut callback: F,
) -> eyre::Result<T> {
    CONSTRAINTS.with(|c| {
        if let Ok(fc) = c.borrow_mut().get_func_constraint_mut(f_name) {
            callback(fc)
        } else {
            log::warn!("fail to find function `{f_name}` in constraint!");
            let mut fc = FuncConstraint::init(f_name)?;
            callback(&mut fc)
        }
    })
}

pub fn iterate_type_constraint_with<F: FnMut(&String, &TypeConstraint) -> eyre::Result<()>>(
    mut callback: F,
) -> eyre::Result<()> {
    CONSTRAINTS.with(|c| {
        for (ty, tc_entries) in c.borrow().type_constraints.iter() {
            callback(ty, tc_entries)?;
        }
        Ok(())
    })
}

pub fn inspect_type_constraint_with<F: FnMut(&TypeConstraint) -> eyre::Result<()>>(
    type_name: &str,
    mut callback: F,
) -> eyre::Result<()> {
    CONSTRAINTS.with(|c| {
        if let Some(tc) = c.borrow().type_constraints.get(type_name) {
            callback(tc)?;
        }
        Ok(())
    })
}

pub fn set_function_constraint_with<F: FnOnce(&mut FuncConstraint)>(
    f_name: &str,
    callback: F,
) -> eyre::Result<()> {
    CONSTRAINTS.with(|c| {
        callback(c.borrow_mut().get_func_constraint_mut(f_name)?);
        Ok(())
    })
}

pub fn add_function_arg_constraint(
    f_name: &str,
    arg_pos: usize,
    constraint: Constraint,
    comment: &str,
) -> eyre::Result<Option<ConstraintSig>> {
    CONSTRAINTS.with(|c| {
        let mut c = c.borrow_mut();
        let fc = c.get_func_constraint_mut(f_name)?;
        let ret = fc.set_constraint(f_name, arg_pos, LocFields::default(), constraint.clone());
        if let Some(c) = &ret {
            log_new_constraint(&format!("{c:?}, comment: {comment}"));
        }
        Ok(ret)
    })
}

pub fn add_function_constraint(
    f_name: &str,
    arg_pos: usize,
    fields: LocFields,
    constraint: Constraint,
    comment: &str,
) -> eyre::Result<Option<ConstraintSig>> {
    CONSTRAINTS.with(|c| {
        let mut c = c.borrow_mut();
        let fc = c.get_func_constraint_mut(f_name)?;
        let ret = fc.set_constraint(f_name, arg_pos, fields.clone(), constraint.clone());
        if let Some(c) = ret.as_ref() {
            crate::log!(trace, "{comment}");
            log_new_constraint(&format!("{c:?}, comment: {comment}"));
        }
        Ok(ret)
    })
}

#[inline]
pub fn filter_forbidden_context(target: &str, f_name: &str, arg_pos: Option<usize>) -> bool {
    CONSTRAINTS.with(|c| {
        c.borrow()
            .get_func_constraint(target)
            .map_or(false, |c| c.is_forbidden_ctx(f_name, arg_pos))
    })
}

impl Constraints {
    /// Init function's constraints
    pub fn init_func_constraint(&mut self, f_name: &str) -> eyre::Result<()> {
        let fc = FuncConstraint::init(f_name)?;
        self.func_constraints.insert(f_name.to_string(), fc);
        Ok(())
    }

    /// Get function's constraint
    #[inline]
    pub fn get_func_constraint(&self, f_name: &str) -> Option<&FuncConstraint> {
        self.func_constraints.get(f_name)
    }

    /// Get function's mut constraint
    #[inline]
    pub fn get_func_constraint_mut(&mut self, f_name: &str) -> eyre::Result<&mut FuncConstraint> {
        if self.func_constraints.get(f_name).is_none() {
            self.init_func_constraint(f_name)?;
        }
        self.func_constraints
            .get_mut(f_name)
            .ok_or_else(|| eyre::eyre!("fail to get func's constraint: {f_name}"))
    }

    pub fn add_func_context(&mut self, f_name: &str, ctx: CallContext) -> eyre::Result<()> {
        if let Ok(fc) = self.get_func_constraint_mut(f_name) {
            crate::log!(info, "add context on function `{f_name}`: {ctx:?}");
            fc.contexts.push(ctx);
        }
        Ok(())
    }

    pub fn init_type_constraint(&mut self, type_name: &str) -> eyre::Result<()> {
        if self.type_constraints.get(type_name).is_some() {
            return Ok(());
        }
        let tc = TypeConstraint::init(type_name);
        if !tc.list.is_empty() {
            self.type_constraints.insert(type_name.to_string(), tc);
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn get_type_constraint_mut(&mut self, type_name: &str) -> &mut TypeConstraint {
        self.type_constraints
            .entry(type_name.to_string())
            .or_insert_with(|| TypeConstraint::init(type_name))
    }

    fn add_type_constraint(&mut self, type_name: &str, fields: LocFields, constraint: Constraint) {
        let tc = self
            .type_constraints
            .entry(type_name.to_string())
            .or_insert_with(|| TypeConstraint::init(type_name));
        crate::log!(
            info,
            "add constraint on type `{type_name}`, field {fields:?}, c: {constraint:?}"
        );
        tc.set_constraint(fields, constraint);
    }
}

// logging for constraint updates
pub fn log_new_constraint(content: &str) {
    #[cfg(test)]
    {
        print!("log new constraint: {content}");
    }
    #[cfg(not(test))]
    {
        use std::io::prelude::*;
        let path = crate::config::output_file_path("misc/constraint.log");
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .unwrap();
        writeln!(f, "{content}").unwrap();
    }
}

#[cfg(all(feature = "testsuite", not(test)))]
pub fn check_contraints_in_testsuite() -> (bool, bool) {
    use once_cell::sync::OnceCell;
    #[derive(Debug)]
    enum ToCheck {
        Constraint(ConstraintSig),
        Opaque(String),
    }
    static TO_CHECK: OnceCell<Vec<ToCheck>> = OnceCell::new();
    let check_list = TO_CHECK.get_or_init(|| {
        let mut list = vec![];
        if let Ok(content) = std::env::var("TESTSUITE_INFER") {
            for line in content.split(';') {
                let line = line.trim_start();
                if line.is_empty() {
                    continue;
                }
                crate::log!(trace, "to check: {line:?}");
                let mut de = crate::Deserializer::new(line, None);
                if line.starts_with('@') {
                    for c in parse::parse_func_constraint(&mut de).unwrap() {
                        list.push(ToCheck::Constraint(c));
                    }
                } else {
                    let (type_name, _fields, _is_pointer) =
                        parse::parse_type_lvalue(&mut de).unwrap();
                    de.trim_start();
                    if de.strip_token("$opaque") {
                        list.push(ToCheck::Opaque(type_name));
                    }
                }
            }
            crate::log!(info, "to check constraints: {list:?}");
        }
        list
    });
    if check_list.is_empty() {
        return (false, false);
    }
    if check_list.iter().all(|to_check| match to_check {
        ToCheck::Constraint(sig) => {
            filter_function_field_constraint_with(&sig.f_name, sig.arg_pos, &sig.fields, |c| {
                c == &sig.constraint
            })
        }
        ToCheck::Opaque(ty_name) => crate::utils::is_opaque_type(ty_name),
    }) {
        log!(trace, "All constraint is passed");
        return (true, true);
    }
    (true, false)
}
