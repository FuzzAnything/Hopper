//! Call statement
//! format: call fn_name(args)

use std::{cell::RefCell, rc::Rc};

use super::*;
use crate::{feedback::globl, global_gadgets, runtime::*, utils};

// det_index: better to be independent of program?
#[derive(Debug)]
pub struct CallStmt {
    /// ident name
    pub ident: String,
    /// function name
    pub name: String,
    /// function gadget
    pub fg: FnGadget,
    /// arguments
    pub args: Vec<StmtIndex>,
    /// return object
    pub ret: Option<FuzzObject>,
    /// ir of return object
    pub ret_ir: Vec<CallRetIR>,
    /// affect by relative or implicit calls
    pub contexts: Vec<StmtIndex>,
    /// track its coverage or not
    pub track_cov: bool,
    /// failure: crash or hang at this call
    pub failure: bool,
    /// Index for deterministic mutation
    pub det_index: Rc<RefCell<usize>>,
}

#[derive(Debug)]
pub struct CallRetIR {
    pub fields: LocFields,
    pub value: FuzzObject,
    pub state: Box<ObjectState>,
    pub used: Option<WeakStmtIndex>,
}

impl StmtView for CallStmt {
    const KEYWORD: &'static str = "call";

    fn get_value(&self) -> Option<&FuzzObject> {
        self.ret.as_ref()
    }

    fn eval(
        &mut self,
        used_stmts: &mut [IndexedStmt],
        resource_states: &mut ResourceStates,
    ) -> eyre::Result<()> {
        crate::log!(
            trace,
            "call {} with args: {}",
            self.name,
            self.args.serialize()?
        );
        let p_start_at = std::time::Instant::now();
        resource_states.check_arguments(&self.args, used_stmts)?;
        let check_secs = p_start_at.elapsed().as_micros();
        crate::log!(trace, "check arg time: {} micro seconds", check_secs);
        let arguments: Vec<&FuzzObject> = self
            .args
            .iter()
            .map(|i| i.get_stmt_value(used_stmts).unwrap())
            .collect();
        crate::log!(trace, "arguments: {:?}", arguments);
        // enable track coverage for this function call or not
        if self.track_cov {
            globl::enable_coverage_feedback();
            if crate::config::get_api_sensitive_cov() {
                let context = hash_context(self.fg.f_name);
                // crate::log!(trace, "context: {context}");
                globl::set_coverage_context(context);
            } else {
                globl::set_coverage_context(0);
            }
        } else {
            globl::disable_coverage_feedback();
        }
        let ret = self.fg.f.eval(&arguments);
        let eval_secs = p_start_at.elapsed().as_micros() - check_secs;
        crate::log!(trace, "eval time: {} micro seconds", eval_secs);
        globl::disable_coverage_feedback();
        crate::log!(trace, "return ({}): {:?}", ret.type_name(), ret);
        self.ret = Some(ret);
        resource_states.update_pointers_after_call()?;
        let update_secs = p_start_at.elapsed().as_micros() - eval_secs;
        crate::log!(trace, "update time: {} micro seconds", update_secs);
        Ok(())
    }
}

impl CallStmt {
    pub fn new(ident: String, name: String, fg: FnGadget) -> Self {
        Self {
            ident,
            name,
            fg,
            args: vec![],
            ret: None,
            ret_ir: vec![],
            contexts: vec![],
            track_cov: false,
            failure: false,
            det_index: Rc::new(RefCell::new(0)),
        }
    }

    /// Set argument
    pub fn set_arg(&mut self, arg_pos: usize, stmt: StmtIndex) {
        if self.args.len() <= arg_pos {
            self.args.push(stmt)
        } else {
            self.args[arg_pos] = stmt;
        }
    }

    /// If previous call contains any context or not
    pub fn has_any_context(&self, program: &FuzzProgram, f_name: &str) -> bool {
        self.has_implicit_context(program, f_name) || self.has_relative_context(program, f_name)
    }

    /// If previous call contains relative context or not
    pub fn has_relative_context(&self, program: &FuzzProgram, f_name: &str) -> bool {
        self.args
            .iter()
            .any(|arg_stmt| Self::has_relative_context_for_stmt(program, f_name, arg_stmt))
    }

    /// If previous call contains relative context for specific statement or not
    pub fn has_relative_context_for_stmt(
        program: &FuzzProgram,
        f_name: &str,
        arg_stmt: &StmtIndex,
    ) -> bool {
        for is in program.stmts.iter() {
            if is.stmt.is_stub() {
                break;
            }
            if let FuzzStmt::Call(call) = &is.stmt {
                if call.fg.f_name == f_name
                    && call.is_relative()
                    && call.is_related_call_for_stmt(arg_stmt, program)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Check if `self` is `call`'s relative call, find the overlap arg
    pub fn has_overlop_arg(&self, program: &FuzzProgram, call: &CallStmt) -> Option<usize> {
        self.args.iter().position(|arg_stmt| call.is_related_call_for_stmt(arg_stmt, program))
    }

    /// If the call contains implicit context or not
    pub fn has_implicit_context(&self, program: &FuzzProgram, f_name: &str) -> bool {
        for ctx in &self.contexts {
            if let Some(is) = program.get_stmt_by_index_uniq(ctx) {
                if let FuzzStmt::Call(call) = &is.stmt {
                    if call.fg.f_name == f_name {
                        crate::log!(trace, "call has context");
                        return true;
                    }
                } else {
                    // eyre::bail!(format!("stmt is not a call for implicit context: {ctx:?}"));
                }
            }
        }
        false
    }

    /// Is this call is relative for a specific statement,
    /// We search the call's arguments recursively.
    pub fn is_related_call_for_stmt(&self, stmt: &StmtIndex, program: &FuzzProgram) -> bool {
        if self.args.contains(stmt) {
            return true;
        }
        let mut relative_indices: Vec<StmtIndex> = self.args.iter().map(|i| i.use_index()).collect();
        while let Some(i) = relative_indices.pop() {
            if let Some(is) = program.get_stmt_by_index_uniq(&i) {
                if let FuzzStmt::Load(load) = &is.stmt {
                    let cb = |index: &StmtIndex| {
                        relative_indices.push(index.use_index());
                        stmt == index
                    };
                    if load.state.find_any_stmt_in_state_with(cb) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Is this call is relative for a specific statement, which uses a pointer to the statement,
    /// Only check the pointee itself, we do not check recursively in this function.
    pub fn is_related_call_for_ptee(&self, ptee_stmt: usize, program: &FuzzProgram) -> bool {
        for cur_arg in self.args.iter() {
            if let Some(is) = program.get_stmt_by_index_uniq(cur_arg) {
                if let FuzzStmt::Load(load) = &is.stmt {
                    if let Some(dst_index) = load.state.get_pointer_stmt_index() {
                        if dst_index.get() == ptee_stmt {
                            return true;
                        }
                    }
                } else {
                    // is not a load
                }
            }
        }
        false
    }

    /// If current arguments has one that been used multiple times
    pub fn has_reused_args(&self, program: &FuzzProgram) -> Option<usize> {
        for (i, arg_index) in self.args.iter().enumerate() {
            if arg_index.get_ref_used() > 2 {
                // crate::log!(trace, "arg_i {i} has >2 ref");
                return Some(i);
            }
            if let Some(is) = program.get_stmt_by_index_uniq(arg_index) {
                if let FuzzStmt::Load(load) = &is.stmt {
                    //load.state.find_any_stmt_in_state_with(|ptee| ptee.get_ref_used() > 2)
                    if let Some(dst_index) = load.state.get_pointer_stmt_index() {
                        if dst_index.get_ref_used() > 2 {
                            // crate::log!(trace, "{} in arg_i {i} has >2 ref", dst_index.get());
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    /// If it is a function for init opaque pointer
    pub fn is_init_opaque_ptr_func(&self) -> bool {
        if !self.is_relative() {
            return false;
        }
        for i in 0..self.args.len() {
            if let Some(inner) = utils::get_pointer_inner(self.fg.arg_types[i]) {
                if utils::is_opaque_pointer(inner) {
                    return true;
                }
            }
        }
        false
    }

    /// target call
    pub const TARGET: &'static str = "$target";
    /// relative call
    pub const RELATIVE: &'static str = "$relative";
    /// implicit call
    pub const IMPLICIT: &'static str = "$implicit";

    /// Is target call
    pub fn is_target(&self) -> bool {
        self.ident == Self::TARGET
    }

    /// Is relative call
    pub fn is_relative(&self) -> bool {
        self.ident == Self::RELATIVE
    }

    /// Is implicit call
    pub fn is_implicit(&self) -> bool {
        self.ident == Self::IMPLICIT
    }

    /// Call that can be leaf node
    pub fn is_leaf(&self) -> bool {
        self.is_target() || self.is_relative() || self.is_implicit()
    }
}

impl CloneProgram for CallStmt {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        Self {
            ident: self.ident.clone(),
            name: self.name.clone(),
            fg: self.fg.clone(),
            args: self.args.clone_with_program(program),
            ret: self.ret.clone(),
            ret_ir: self
                .ret_ir
                .iter()
                .map(|c| c.clone_with_program(program))
                .collect(),
            contexts: self.contexts.clone_with_program(program),
            track_cov: self.track_cov,
            failure: self.failure,
            det_index: self.det_index.clone(),
        }
    }
}

impl CloneProgram for CallRetIR {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        Self {
            fields: self.fields.clone(),
            value: self.value.clone(),
            state: self.state.clone_with_program(program),
            used: self.used.clone_with_program(program),
        }
    }
}

impl CloneProgram for Vec<StmtIndex> {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        self.iter().map(|i| i.clone_with_program(program)).collect()
    }
}

impl From<CallStmt> for FuzzStmt {
    fn from(stmt: CallStmt) -> Self {
        FuzzStmt::Call(Box::new(stmt))
    }
}

impl Serialize for CallStmt {
    fn serialize(&self) -> eyre::Result<String> {
        let args = serialize_args(&self.args)?;
        let track_sym = option_sym(self.track_cov, "? ");
        let failure_sym = option_sym(self.failure, "! ");
        let mut implicit_calls = String::new();
        if !self.contexts.is_empty() {
            implicit_calls.push_str("<- ");
            implicit_calls.push_str(&serialize_args(&self.contexts)?);
        }
        Ok(format!(
            "{} {}: {} {}{}{} {}",
            Self::KEYWORD,
            self.ident,
            self.name,
            track_sym,
            failure_sym,
            args,
            implicit_calls
        ))
    }
}

impl Deserialize for CallStmt {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        // de.strip_token(Self::KEYWORD);
        de.trim_start();
        let ident = de.next_token_until(":")?;
        let fn_name = de.next_token_until(" ")?;
        let track_sym = parse_sym(de, "?");
        let failure_sym = parse_sym(de, "!");
        let args = deserialize_args(de)?;
        let mut implicit_calls = vec![];
        if de.strip_token("<-") {
            de.trim_start();
            implicit_calls = deserialize_args(de)?;
        }
        let fg = global_gadgets::get_instance()
            .get_func_gadget(fn_name)?
            .clone();
        Ok(CallStmt {
            ident: ident.to_string(),
            name: fn_name.to_string(),
            fg,
            args,
            ret: None,
            ret_ir: vec![],
            contexts: implicit_calls,
            track_cov: track_sym,
            failure: failure_sym,
            det_index: Rc::new(RefCell::new(0)),
        })
    }
}

fn option_sym(cond: bool, sym: &str) -> &str {
    if cond {
        sym
    } else {
        ""
    }
}

fn parse_sym(de: &mut Deserializer, sym: &str) -> bool {
    let mut has_sym = false;
    if de.strip_token(sym) {
        has_sym = true;
    }
    de.trim_start();
    has_sym
}

fn serialize_args(args: &[StmtIndex]) -> eyre::Result<String> {
    let mut content = String::new();
    content.push('(');
    for i in args {
        content.push_str(&i.serialize()?);
        content.push_str(", ");
    }
    content.push(')');
    Ok(content)
}

fn deserialize_args(de: &mut Deserializer) -> eyre::Result<Vec<StmtIndex>> {
    let mut args = vec![];
    de.eat_token("(")?;
    loop {
        if de.strip_token(")") {
            break;
        }
        let stmt_index = StmtIndex::deserialize(de)?;
        de.eat_token(",")?;
        args.push(stmt_index);
    }
    de.trim_start();
    Ok(args)
}

fn hash_context(f_name: &str) -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    f_name.hash(&mut hasher);
    (hasher.finish() & (crate::config::BRANCHES_SIZE as u64 - 1)) as u32
}
