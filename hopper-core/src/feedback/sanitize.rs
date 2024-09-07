use eyre::ContextCompat;
use hopper_derive::Serde;
use std::fmt;
use std::fmt::Display;

use crate::{
    config,
    runtime::*,
    utils::{self, FileAppender},
    CrashSig,
};

use super::{MemType, ResourceStates};

pub const SANITIZER_FLAG_NUM: u8 = 3;

pub const REF_CIRCLE_FLAG: &str = "refcircle";
pub const ILL_FREE_FLAG: &str = "illfree";
pub const NOT_TARGET_FLAG: &str = "nottarget";
pub const GENERATE_FLAG: &str = "generate";
pub const SET_ALL_FLAG: &str = "all";

#[derive(Debug, Default, Serde)]
pub struct SanitizeResult {
    pub cause: Vec<FailureCause>,
}

pub struct SanitizeChecker {
    pub appender: FileAppender,
}

#[derive(Debug, Serde, Clone)]
pub enum FailureCause {
    RefCircle {
        stmt: usize,
        field1: LocFields,
        field2: LocFields,
    },
    DoubleFree {
        freed_addr: u64,
    },
    IllegalFree {
        freed_addr: u64,
    },
    NotTrackCall {
        fail_at: usize,
    },
    SegViolation {
        addr: CrashSig,
    },
    ViolateRule {
        rule: String,
    },
    Generate,
}

impl SanitizeChecker {
    pub fn new() -> eyre::Result<Self> {
        Ok(Self {
            appender: FileAppender::create(config::tmp_file_path("sanitize"))?,
        })
    }

    pub fn check_before_eval_stmt(
        &mut self,
        is: &IndexedStmt,
        used_stmts: &[IndexedStmt],
        resource_states: &ResourceStates,
    ) -> eyre::Result<()> {
        if let FuzzStmt::Call(call) = &is.stmt {
            self.check_reference_circle(call, used_stmts, resource_states)?;
            self.check_not_target_call(call, is.index.get())?;
        }
        Ok(())
    }

    pub fn check_reference_circle(
        &mut self,
        call: &CallStmt,
        used_stmts: &[IndexedStmt],
        resource_states: &ResourceStates,
    ) -> eyre::Result<()> {
        if call.failure {
            for arg_stmt in call.args.iter() {
                let value = arg_stmt.get_stmt_value(used_stmts).context("has value")?;
                // crate::log!(trace, "checking argument: {:#?}", value);
                let layout = value.get_layout(false);

                let is_ref_circle = layout.check_reference_circle(resource_states);
                let ref_circle_locs = layout.check_reference_circle_loc(resource_states);
                if is_ref_circle != ref_circle_locs.is_some() {
                    crate::log!(warn, "sanitize result inconsitent");
                }
                if let Some((field1, field2)) = ref_circle_locs {
                    self.appender.append(&FailureCause::RefCircle {
                        stmt: arg_stmt.get(),
                        field1,
                        field2,
                    })?;
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn check_not_target_call(&mut self, call: &CallStmt, index: usize) -> eyre::Result<()> {
        if call.failure && !call.track_cov {
            self.appender
                .append(&FailureCause::NotTrackCall { fail_at: index })?;
        }
        Ok(())
    }

    pub fn check_generate(&mut self, program: &FuzzProgram) -> eyre::Result<()> {
        if program.parent.is_none() {
            self.appender.append(&FailureCause::Generate)?;
        }
        Ok(())
    }

    pub fn check_illegal_free(index: usize) -> Vec<FailureCause> {
        let instrs = super::get_instr_list();
        let mut allocated = vec![];
        let mut freed = vec![];
        let mut hints = vec![];
        for mem in instrs.mem_iter() {
            let addr = { mem.addr };
            match mem.get_type() {
                MemType::Malloc | MemType::Calloc | MemType::ReallocMalloc => {
                    allocated.push(addr);
                    freed.retain(|v| v != &addr);
                }
                MemType::Free | MemType::ReallocFree => {
                    if mem.stmt_index as usize == index {
                        if freed.contains(&addr) {
                            hints.push(FailureCause::DoubleFree { freed_addr: addr });
                        } else if !allocated.contains(&addr) {
                            hints.push(FailureCause::IllegalFree { freed_addr: addr });
                        }
                    }
                    freed.push(addr);
                }
                _ => {}
            }
        }
        hints
    }
}

impl SanitizeResult {
    pub fn add_violated_constraints<T: Serialize>(
        &mut self,
        constraints: &[T],
    ) -> eyre::Result<()> {
        if constraints.is_empty() {
            return Ok(());
        }
        let mut buf = String::new();
        for c in constraints {
            buf.push_str(&c.serialize()?);
            buf.push_str(", ");
        }
        self.cause.push(FailureCause::ViolateRule { rule: buf });
        Ok(())
    }

    pub fn conclusion(program: &FuzzProgram) -> eyre::Result<Self> {
        let mut cause = utils::read_list_from_file(config::tmp_file_path("sanitize"))?;
        let instr = crate::get_instr_list();
        let last_stmt = instr.last_stmt_index();
        let result = SanitizeChecker::check_illegal_free(last_stmt);
        cause.extend(result);
        if let Some(addr) = crate::get_crash_sig(Some(program)) {
            cause.push(FailureCause::SegViolation { addr });
        }
        Ok(Self { cause })
    }
}

impl Display for SanitizeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.cause.is_empty() {
            return Ok(());
        }
        writeln!(f, 
            "<SANITIZER> Program crashes or hangs may be due to the following reasons: "
        )?;
        for cause in &self.cause {
            writeln!(f, "\t* {cause}")?;
        }
        Ok(())
    }
}

impl Display for FailureCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RefCircle {
                stmt,
                field1,
                field2,
            } => {
                write!(
                    f,
                    "A reference circle in the arguments of the crashed call is detected. statement: {}, fields: {} and {}",
                    stmt, field1.serialize().unwrap(), field2.serialize().unwrap()
                )
            }
            Self::DoubleFree { freed_addr } => {
                write!(
                    f,
                    "A double-free is detected (address: {freed_addr:p}), where the pointer has been freed in other place before it."
                )
            }
            Self::IllegalFree { freed_addr } => {
                write!(
                    f,
                    "An illegal call of free() is detected (address: {freed_addr:p}), where the freed pointer is not properly allocatecd. This happens when the pointer is obtained from a field of another object."
                )
            }
            Self::NotTrackCall { fail_at } => {
                write!(
                    f,
                    "The program failed at call <{fail_at}>, which is not in its tracking call."
                )
            }
            Self::SegViolation { addr } => {
                write!(
                    f,
                    "Segmentation violation at memory {:?} and RIP {:?} : {}",
                    addr.get_addr(),
                    addr.get_rip(),
                    addr.reason()
                )
            }
            Self::Generate => {
                write!(f, "The program is generated from nothing.")
            }
            Self::ViolateRule { rule } => {
                write!(f, "Violate constraint: {rule}")
            }
        }
    }
}

impl ObjectLayout {
    /// Check reference circle, and return the location of pointer that crates the circle.
    pub fn check_reference_circle_loc(
        &self,
        resource_states: &ResourceStates,
    ) -> Option<(LocFields, LocFields)> {
        let mut cur_path = vec![];
        let mut visited_ptr = vec![];
        if let Some(ptr) = self.check_reference_circle_loc_inner(
            resource_states,
            &mut cur_path,
            &mut visited_ptr,
            std::ptr::null_mut(),
            0,
        ) {
            let loc1 = self.find_ptr(ptr, resource_states).unwrap();
            let loc2 = LocFields::new(cur_path);
            return Some((loc1, loc2));
        }
        None
    }

    pub fn check_reference_circle_loc_inner(
        &self,
        resource_states: &ResourceStates,
        cur_path: &mut Vec<FieldKey>,
        visited_ptr: &mut Vec<*mut u8>,
        last_ptr: *mut u8,
        depth: usize,
    ) -> Option<*mut u8> {
        if depth > 64 || self.ptr.is_null() {
            return None;
        }
        // avoid backtracing fields, e.g. prev, parent..
        // they will be circle in real worlds
        if let FieldKey::Field(f) = &self.key {
            if crate::literal::is_backtracing_field(f) {
                return None;
            }
        }
        crate::log!(
            trace,
            "visit: {:?} - {:?}  - last: {:?}",
            cur_path,
            self.ptr,
            last_ptr
        );
        // Avoid first field or index in structure or array.
        // e.g a = A { f1, f2 } , &a = &(a.f1)
        // they will hold the same address
        let not_first_field = self.ptr != last_ptr;
        // Pointer key is special, if &a = a.f1, it is a ref-circle
        if (not_first_field || self.key == FieldKey::Pointer) && visited_ptr.contains(&self.ptr) {
            crate::log!(trace, "ptr {:?} is ref-circle", self.ptr);
            return Some(self.ptr);
        }
        if not_first_field {
            visited_ptr.push(self.ptr);
        }
        let fields = self.get_fields_with_rs(resource_states);
        for f in fields {
            if let FieldKey::Index(_) = f.key {
                if f.fields.is_empty() && f.lazy_loader.is_none() {
                    break;
                }
            }
            /*
            // only focus on types that : T { field : T* }
            if let FieldKey::Field(_) = &f.key {
                if !self.type_name.contains(f.type_name) {
                    return false;
                }
            }
            */
            cur_path.push(f.key.clone());
            let ret = f.check_reference_circle_loc_inner(
                resource_states,
                cur_path,
                visited_ptr,
                self.ptr,
                depth + 1,
            );
            if ret.is_some() {
                return ret;
            }
            cur_path.pop();
        }
        None
    }

    pub fn get_concrete_objs<'a>(
        &'a self,
        objs: &mut Vec<&'a ObjectLayout>,
        resource_states: &ResourceStates,
    ) {
        match self.key {
            FieldKey::Pointer => {
                let fields = self.get_fields_with_rs(resource_states);
                for f in fields {
                    f.get_concrete_objs(objs, resource_states);
                }
            }
            FieldKey::Index(_) => {
                let fields = self.get_fields_with_rs(resource_states);
                for f in fields {
                    if let FieldKey::Field(_) = f.key {
                        objs.push(self);
                        return;
                    }
                }

                // If this is a multi-level pointer
                for f in fields {
                    f.get_concrete_objs(objs, resource_states);
                }
            }

            // Only falls in here when invoked in check_reference_circle_recurse
            FieldKey::Field(_) | FieldKey::Root(_) => {
                if utils::is_pointer_type(self.type_name) {
                    let fields = self.get_fields_with_rs(resource_states);
                    for f in fields {
                        f.get_concrete_objs(objs, resource_states);
                    }
                } else if !utils::is_option_type(self.type_name)
                    && !utils::is_primitive_type(self.type_name)
                {
                    objs.push(self)
                }
            }
            _ => {}
        }
    }

    pub fn check_reference_circle(&self, resource_states: &ResourceStates) -> bool {
        self.check_reference_circle_inner(resource_states, 0)
    }

    fn check_reference_circle_inner(&self, resource_states: &ResourceStates, depth: usize) -> bool {
        if depth > 1 {
            return false;
        }
        let mut objs: Vec<&ObjectLayout> = vec![];
        self.get_concrete_objs(&mut objs, resource_states);
        crate::log!(trace, "check_reference_circle: concrete objs: {:?}", objs);
        for obj in objs {
            let fields = obj.get_fields_with_rs(resource_states).iter().filter(|l| {
                let mut ident_name_flag = false;
                if let FieldKey::Field(key) = &l.key {
                    ident_name_flag = !crate::literal::is_backtracing_field(key);
                }
                let type_name_flag = if let Some(inner_ty) = utils::get_pointer_inner(l.type_name) {
                    inner_ty == obj.type_name
                } else {
                    false
                };
                ident_name_flag && type_name_flag
            });
            let field_keys = fields.fold(vec![], |mut acc, l| {
                if let FieldKey::Field(key) = &l.key {
                    acc.push(key.as_str());
                }
                acc
            });
            crate::log!(trace, "Elected Fields: {:?}", field_keys);

            let mut visited_ptrs = vec![];
            if obj.check_reference_circle_recurse(
                &mut visited_ptrs,
                &field_keys,
                resource_states,
                depth,
            ) {
                return true;
            }
        }
        false
    }

    fn check_reference_circle_recurse(
        &self,
        visited_ptrs: &mut Vec<*mut u8>,
        field_keys: &Vec<&str>,
        resource_states: &ResourceStates,
        depth: usize,
    ) -> bool {
        for layout in self.get_fields_with_rs(resource_states) {
            crate::log!(trace, "Current Layout: {:?}", layout);
            if let FieldKey::Field(key) = &layout.key {
                if !field_keys.contains(&key.as_str()) {
                    if layout.check_reference_circle_inner(resource_states, depth + 1) {
                        return true;
                    }
                    continue;
                }
                if visited_ptrs.contains(&layout.ptr) {
                    crate::log!(trace, "ptr {:?} is visited", layout.ptr);
                    return true;
                }
                visited_ptrs.push(layout.ptr);
            }
            let found = layout.check_reference_circle_recurse(
                visited_ptrs,
                field_keys,
                resource_states,
                depth,
            );
            if found {
                return found;
            }
        }
        false
    }
}

#[test]
fn test_reference_circle_checker() {
    for i in 1..=4 {
        println!("run test case {i}");
        let mut call = crate::test::generate_call_stmt(&format!("reference_circle_{i}"));
        let mut resource_states = ResourceStates::default();
        use crate::StmtView;
        call.eval(&mut [], &mut resource_states).expect("...");
        let layout = call.ret.unwrap().get_layout(false);
        assert!(layout.check_reference_circle(&resource_states));
        let path = layout.check_reference_circle_loc(&resource_states);
        println!("locs: {path:?}");
        assert!(path.is_some());
    }
}
