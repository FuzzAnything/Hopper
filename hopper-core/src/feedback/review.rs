use eyre::{Context, ContextCompat};
use hopper_derive::Serde;
use std::fmt::Write as _;

use crate::{
    feedback::*,
    runtime::*,
    utils::{self, FileAppender},
};

/// Review program executation, records some useful information for fuzzing
#[derive(Debug, Default)]
pub struct ReviewResult {
    /// List of compare functions
    pub cmp_records: Vec<CmpRecord>,
    /// List of memory related functions
    pub mem_records: Vec<MemRecord>,
    /// List of call returns
    pub call_rets: Vec<CallRet>,
}

pub struct ReviewCollector {
    pub cmp_appender: FileAppender,
    pub mem_appender: FileAppender,
    pub ret_appender: FileAppender,
}

/// Record of Compare function, e.g. strcmp, memcmp ..
/// if strcmp(p1, p2) and we find that p2 is a static value,
/// then it indicates that p1(loc) should be mutate as p2's value (buf)
#[derive(Debug, Serde)]
pub struct CmpRecord {
    /// Call statement index
    pub call_index: usize,
    /// Id of instrumentation
    pub id: u32,
    /// Mutate location
    pub loc: Location,
    /// Expect value of the function
    pub buf: Vec<u8>,
}

/// Record of memory related function, e.g. malloc, free ..
/// It records the latest memory size of location `loc`.
/// If visit `free(p)`, p is a loc, then p's memory size is 0 and we record (p, 0);
/// If visit `p = mallo(1024)`, then p's memory size is 1024, and we record (p, 1024).
#[derive(Debug, Serde)]
pub struct MemRecord {
    /// Call statement index
    pub call_index: usize,
    /// Id of instrumentation
    pub id: u32,
    /// Memory location
    pub loc: Location,
    /// Mutate size
    pub size: usize,
    /// Is read mode
    pub mode: usize,
    /// Record type
    pub ty: u16,
}

impl MemRecord {
    pub fn is_mem_op(&self) -> bool {
        self.ty < 90
    }
}

/// Call's return
/// It has two representation, we use `origin` during evaluation,
/// and `ir` during mutatiuon.
#[derive(Debug, Default)]
pub struct CallRet {
    /// Call statement index
    pub call_index: usize,
    // is from static, e.g. global variables or static string
    pub static_ret: bool,
    // is unwritable, functions may return a pointer that points to a constant value sometimes
    pub unwritable_ret: bool,
    // init argument
    pub init_arg: bool,
    // is partial opaque, some of the fields in the return are hidden.
    pub partial_opaque_ret: bool,
    // raw value: serialize after evaluation
    pub raw: Option<String>,
    // load value: used for mutating
    pub ir: Vec<CallRetIR>,
}

fn review_file_path(id: usize, kind: &str) -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(crate::config::OUTPUT_DIR);
    path.push(crate::config::REVIEW_DIR);
    path.push(format!("{id}_{kind}"));
    path
}

impl ReviewCollector {
    pub fn new(id: usize) -> eyre::Result<Self> {
        Ok(Self {
            cmp_appender: FileAppender::create(review_file_path(id, "cmp"))?,
            mem_appender: FileAppender::create(review_file_path(id, "mem"))?,
            ret_appender: FileAppender::create(review_file_path(id, "ret"))?,
        })
    }

    /// Collect review after function call
    pub fn collect_call_review(
        &mut self,
        call: &CallStmt,
        index: usize,
        prev_stmts: &[IndexedStmt],
        resource_states: &ResourceStates,
    ) -> eyre::Result<()> {
        crate::log_c!(trace, "start call review");
        let instrs = super::get_instr_list();
        let cmp_records = instrs.associate_loc_with_cmp_fn(index, prev_stmts, resource_states);
        self.cmp_appender
            .append_list(&cmp_records)
            .context("fail to write cmp records")?;
        let mem_records = instrs.associate_loc_with_mem_op(index, prev_stmts, resource_states);
        self.mem_appender
            .append_list(&mem_records)
            .context("fail to write mem records")?;
        let init_arg = is_init_func(call, prev_stmts)?;
        // Collect call ret
        if let Some(ret_type) = call.fg.ret_type {
            if let Some(ret) = &call.ret {
                let is_opaque = utils::is_opaque_pointer(ret_type);
                crate::log_c!(trace, "ret type: {}, is_opaque: {}", ret_type, is_opaque);
                if !is_opaque {
                    let call_ret = CallRet {
                        call_index: index,
                        static_ret: is_static_ret(ret, ret_type)?,
                        unwritable_ret: is_unwritable_ret(ret, ret_type)?,
                        init_arg,
                        partial_opaque_ret: is_partial_opaque_ret(ret, ret_type, resource_states)?,
                        raw: Some(serialize_call_ret(ret, resource_states)?),
                        ir: vec![],
                    };
                    self.ret_appender.append(&call_ret)?;
                    return Ok(());
                }
            }
        }
        if init_arg {
            let call_ret = CallRet {
                call_index: index,
                init_arg,
                ..Default::default()
            };
            self.ret_appender.append(&call_ret)?;
        }
        Ok(())
    }
}

impl ReviewResult {
    /// Attach information during review to program
    pub fn attach_into_program(self, program: &mut FuzzProgram) -> eyre::Result<()> {
        // crate::log!(debug, "review result: {:?}", self);
        self.add_into_constraints(program)?;
        set_program_call_returns(program, self.call_rets).context("fail to set call returns")?;
        set_program_cmp_records(program, self.cmp_records).context("fail to set cmp records")?;
        set_program_mem_records(program, self.mem_records).context("fail to set mem records")?;
        program
            .check_update()
            .context("fail to check update for return")?;
        Ok(())
    }

    /// Add review's result into constraints
    pub fn add_into_constraints(&self, program: &FuzzProgram) -> eyre::Result<()> {
        for ret in &self.call_rets {
            let call_is = &program
                .stmts
                .get(ret.call_index)
                .context("fail to find index")?;
            if let FuzzStmt::Call(call) = &call_is.stmt {
                let call_name = call.fg.f_name;
                let id = program.id;
                // Find calls that init opaque objects.
                if ret.init_arg {
                    crate::set_function_constraint_with(call.fg.f_name, |fc| {
                        if !fc.role.init_arg {
                            fc.role.init_arg = true;
                            crate::log_new_constraint(&format!(
                                "found {call_name} will init its arg in seed {id}",
                            ));
                        }
                    })?;
                }
                // Find calls return pointer to static variable
                if ret.static_ret {
                    crate::set_function_constraint_with(call_name, |fc| {
                        if !fc.ret.is_static {
                            fc.ret.is_static = true;
                            crate::log_new_constraint(&format!(
                                "found {call_name} 's return is static in seed {id}",
                            ));
                        }
                    })?;
                }
                // Find calls return pointer to unwritable memory
                if ret.unwritable_ret {
                    crate::log!(trace, "{call_name} returns unwritable calls");
                    crate::set_function_constraint_with(call_name, |fc| {
                        if !fc.ret.is_unwriteable {
                            fc.ret.is_unwriteable = true;
                            crate::log_new_constraint(&format!(
                                "found {call_name} 's return is unwritable in seed {id}",
                            ));
                        }
                    })?;
                }
                if ret.partial_opaque_ret {
                    crate::log!(
                        trace,
                        "{call_name} returns a pointer that is partial opaque."
                    );
                    crate::set_function_constraint_with(call_name, |fc| {
                        if !fc.ret.is_partial_opaque {
                            fc.ret.is_partial_opaque = true;
                            crate::log_new_constraint(&format!(
                                "found {call_name} 's return is partial opaque in seed {id}",
                            ));
                        }
                    })?;
                }
            }
        }
        // file constraint
        self.infer_file_name(program)?;
        Ok(())
    }

    pub fn read_from_file(program: &mut FuzzProgram) -> eyre::Result<Self> {
        let id = program.id;
        let cmp_records =
            utils::read_list_with_program_from_file(review_file_path(id, "cmp"), program)
                .with_context(|| format!("read from file failed: {id}_cmp"))?;
        let mem_records =
            utils::read_list_with_program_from_file(review_file_path(id, "mem"), program)
                .with_context(|| format!("read from file failed: {id}_mem"))?;
        let call_rets =
            utils::read_list_with_program_from_file(review_file_path(id, "ret"), program)
                .with_context(|| format!("read from file failed: {id}_ret"))?;
        crate::log!(trace, "read review done");
        Ok(Self {
            cmp_records,
            mem_records,
            call_rets,
        })
    }
}

impl FuzzProgram {
    pub fn attach_with_review_result(&mut self) -> eyre::Result<()> {
        let review = ReviewResult::read_from_file(self)?;
        review
            .attach_into_program(self)
            .with_context(|| format!("program failed: {self}"))?;
        Ok(())
    }
}

/// check if a return pointer to static variable
fn is_static_ret(ret: &FuzzObject, type_name: &str) -> eyre::Result<bool> {
    if utils::is_pointer_type(type_name) {
        let ptr = ret.get_ptr_by_keys(&[FieldKey::Pointer])?;
        if !ptr.is_null() && utils::is_in_shlib(ptr) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Check if the return pointer is unwritable
fn is_unwritable_ret(ret: &FuzzObject, type_name: &str) -> eyre::Result<bool> {
    if utils::is_pointer_type(type_name) {
        let ptr = ret.get_ptr_by_keys(&[FieldKey::Pointer])?;
        if !ptr.is_null() && utils::is_unwritable(ptr) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_partial_opaque_ret(
    ret: &FuzzObject,
    type_name: &str,
    resource_states: &ResourceStates,
) -> eyre::Result<bool> {
    if let Some(inner_ty) = utils::get_pointer_inner(type_name) {
        if utils::is_primitive_type(inner_ty) || utils::is_opaque_type(inner_ty) {
            return Ok(false);
        }
        let ptr = ret.get_ptr_by_keys(&[FieldKey::Pointer])?;
        if ptr.is_null() {
            return Ok(false);
        }
        let size = resource_states.get_ptr_size(ptr);
        if let Some(sz) = size {
            let ele_size = global_gadgets::get_instance()
                .get_object_builder(inner_ty)?
                .mem_size();
            if sz > ele_size {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Check if the function is used for initilization
fn is_init_func(call: &CallStmt, prev_stmts: &[IndexedStmt]) -> eyre::Result<bool> {
    for cur_arg in call.args.iter() {
        if let FuzzStmt::Load(load) = &prev_stmts[cur_arg.get()].stmt {
            if let Some(dst_index) = load.state.get_pointer_stmt_index() {
                if let FuzzStmt::Load(load) = &prev_stmts[dst_index.get()].stmt {
                    let ty = load.state.ty;
                    if let Some(inner_ty) = utils::get_vec_inner(ty) {
                        if utils::is_opaque_pointer(inner_ty)
                            && load.state.children.first().map_or(false, |s| s.is_null())
                            && !load
                                .value
                                .get_ptr_by_keys(&[FieldKey::Index(0), FieldKey::Pointer])?
                                .is_null()
                        {
                            return Ok(true);
                        }
                    } else if utils::is_opaque_pointer(ty)
                        && load.state.is_null()
                        && !load.value.get_ptr_by_keys(&[FieldKey::Pointer])?.is_null()
                    {
                        return Ok(true);
                    }
                }
            }
        }
    }
    Ok(false)
}

fn set_program_call_returns(
    program: &mut FuzzProgram,
    call_rets: Vec<CallRet>,
) -> eyre::Result<()> {
    for ret in call_rets {
        let call_is = &mut program.stmts[ret.call_index];
        match &mut call_is.stmt {
            FuzzStmt::Call(call) => {
                call.ret_ir = ret.ir;
                // ignore root (&[]) fields, which is a pointer
                if let Some(first) = call.ret_ir.first_mut() {
                    if first.fields.is_empty() {
                        first.used = Some(call_is.index.downgrade());
                    }
                }
            }
            _ => {
                eyre::bail!(format!("index {} is not a call stmt", ret.call_index));
            }
        }
    }
    Ok(())
}

fn set_program_mem_records(
    program: &mut FuzzProgram,
    mem_records: Vec<MemRecord>,
) -> eyre::Result<()> {
    crate::log!(trace, "set free records ..");
    for r in &mem_records {
        eyre::ensure!(
            r.call_index < program.stmts.len(),
            "index is less than stmts' length"
        );
        // free record
        if r.is_mem_op() && r.size == 0 {
            let fields = &r.loc.fields.list;
            // load : empty fields
            // call : pointer
            if fields.is_empty() || (fields.len() == 1 && fields[0] == FieldKey::Pointer) {
                let stmt_index = r.loc.stmt_index.as_ref().context("loc has index")?;
                let stmt_i = stmt_index.get();
                crate::log!(trace, "stmt {} is freed by call {}", stmt_i, r.call_index);
                // index that use the resource
                let call_index = program.stmts[r.call_index].index.use_index();
                program.stmts[stmt_i].freed = Some(call_index.downgrade());
                // find all indices that used it.
                for is in program.stmts.iter_mut() {
                    if let FuzzStmt::Load(load) = &mut is.stmt {
                        if load
                            .state
                            .find_any_stmt_in_state_with(|ptee| ptee.get() == stmt_i)
                        {
                            is.freed = Some(call_index.downgrade());
                        }
                    }
                    // Call?
                }
                // add free constraint
                if let FuzzStmt::Call(call) = &program.stmts[r.call_index].stmt {
                    let f_name = call.fg.f_name;
                    crate::log!(trace, "call {f_name} will free args");
                    crate::set_function_constraint_with(f_name, |fc| fc.role.free_arg = true)?;
                }
            }
        }
        // size change?
    }
    Ok(())
}

fn set_program_cmp_records(
    program: &mut FuzzProgram,
    cmp_records: Vec<CmpRecord>,
) -> eyre::Result<()> {
    crate::log!(trace, "set cmp records..");
    // cmp inst
    let cmps = get_instr_list().get_cmp_ref_list();
    crate::log!(
        trace,
        "store inst cmp list, program: {}, length: {}",
        program.id,
        cmps.len()
    );
    // eyre::ensure!(!cmps.is_empty(), "should not be empty");
    program.cmps = std::rc::Rc::new(cmps);
    // cmp function
    for r in cmp_records {
        // crate::log!(trace, "r: {r:?}");
        let loc = &r.loc;
        let indexed_stmt = program.get_stmt_by_loc(loc).context("cmp loc error")?;
        let mut fields = loc.fields.as_slice();
        let mut offset = 0;
        if let Some(FieldKey::Index(i)) = fields.last() {
            offset = *i;
            fields = &fields[0..fields.len() - 1];
        }
        let cmp_buf = CmpBuf {
            id: r.id,
            offset,
            buf: r.buf,
            det: true,
        };
        match &indexed_stmt.stmt {
            FuzzStmt::Load(load) => {
                // The layout of an object might be changed after relative function calls or UPDATE statements,
                // while the state of that object remains the same ever since it's loaded or serialized from a call.
                // The discrepancies here is unavoidable and thus we should exempt the attachment of cmp records from falling into errors
                // if a field is not found in an outdated object state.
                if let Ok(state) = load.state.get_child_by_fields(fields) {
                    crate::log!(
                        trace,
                        "load cmp buf {:?} is used in {}",
                        &cmp_buf,
                        loc.serialize()?
                    );
                    // for special case
                    // the array/vec is the first field/element of other structure/vec..
                    let mut first = state.children.first();
                    while let Some(inner) = first {
                        let cmp_buf = cmp_buf.clone();
                        inner.mutate.borrow_mut().affect_cmp_buf(cmp_buf);
                        first = inner.children.first();
                    }
                    state.mutate.borrow_mut().affect_cmp_buf(cmp_buf);
                } else {
                    crate::log!(
                        warn,
                        "attach cmp failed with cmp_buf: {:?} and location: {}",
                        &cmp_buf,
                        loc.serialize()?
                    );
                }
            }
            FuzzStmt::Call(call) => {
                let loc_fields = &loc.fields.list;
                let pos = loc_fields.iter().rposition(|k| k == &FieldKey::Pointer);
                let i = pos.map_or(0, |i| i + 1);
                let (prefix, rest) = loc_fields.split_at(i);
                let call_ir = call.ret_ir.iter().find(|ir| ir.fields.list == prefix);
                if let Some(call_ir) = call_ir {
                    crate::log!(
                        trace,
                        "call cmp buf {:?} is used in {}",
                        &cmp_buf,
                        loc.serialize()?
                    );
                    if let Ok(state) = call_ir.state.get_child_by_fields(rest) {
                        state.mutate.borrow_mut().affect_cmp_buf(cmp_buf);
                    } else {
                        crate::log!(
                            warn,
                            "attach cmp failed with cmp_buf: {:?} and location: {}",
                            &cmp_buf,
                            loc.serialize()?
                        );
                    }
                }
            }
            FuzzStmt::File(_) => {
                // ignore file
            }
            _ => {
                eyre::bail!("stmt is not `load` or `call` type!");
            }
        };
    }
    Ok(())
}

fn serialize_call_ret(
    call_ret: &FuzzObject,
    resource_states: &ResourceStates,
) -> eyre::Result<String> {
    crate::log!(
        trace,
        "start serialize call ret, type: {}",
        call_ret.type_name()
    );
    let layout = call_ret.get_layout(false);
    crate::log!(trace, "layout: {:?}", layout);
    // add it self
    let mut buf = String::new();
    let _ = write!(
        buf,
        "[ ([], {}, {}), ",
        layout.type_name,
        call_ret.serialize()?
    );
    for ir in &layout.serialize_return_object_pointers(resource_states)? {
        buf.push_str(ir);
        buf.push_str(", ")
    }
    buf.push(']');
    crate::log!(trace, "call ret itself: {}", buf);
    Ok(buf)
}

impl Serialize for CallRet {
    fn serialize(&self) -> eyre::Result<String> {
        let buf = self
            .raw
            .as_ref()
            .cloned()
            .unwrap_or_else(|| "[]".to_string());
        let static_ret = self.static_ret.serialize()?;
        let unwritable_ret = self.unwritable_ret.serialize()?;
        let init_arg = self.init_arg.serialize()?;
        let partial_opaque_ret = self.partial_opaque_ret.serialize()?;
        Ok(format!(
            "({}, {}, {}, {}, {}, {})",
            self.call_index, static_ret, unwritable_ret, init_arg, partial_opaque_ret, buf,
        ))
    }
}

impl Deserialize for CallRet {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        de.eat_token("(")?;
        let call_index = de.parse_number()?;
        de.eat_token(",")?;
        let static_ret = bool::deserialize(de)?;
        de.eat_token(",")?;
        let unwritable_ret = bool::deserialize(de)?;
        de.eat_token(",")?;
        let init_arg = bool::deserialize(de)?;
        de.eat_token(",")?;
        let partial_opaque_ret = bool::deserialize(de)?;
        de.eat_token(",")?;
        de.eat_token("[")?;
        let mut ir = vec![];
        loop {
            if de.strip_token("]") {
                break;
            }
            ir.push(CallRetIR::deserialize(de)?);
            de.eat_token(",")?;
        }
        de.eat_token(")")?;
        Ok(Self {
            call_index,
            static_ret,
            init_arg,
            unwritable_ret,
            partial_opaque_ret,
            raw: None,
            ir,
        })
    }
}

impl Deserialize for CallRetIR {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        de.eat_token("(")?;
        let fields = LocFields::deserialize(de)?;
        de.eat_token(",")?;
        let ty_tmp = de.eat_ty()?;
        let ty = utils::get_static_ty(ty_tmp);
        let ident = if let Some(last) = fields.list.last() {
            format!("call_ret_{}", last.as_str()?)
        } else {
            "call_ret".to_string()
        };
        let mut state = Box::new(ObjectState::root(ident, ty));
        let value = read_value(de, ty, &mut state)?;
        de.eat_token(")")?;
        Ok(Self {
            fields,
            value,
            state,
            used: None,
        })
    }
}

#[cfg(test)]
pub fn convert_ret_to_ir(ret: &FuzzObject, resource_states: &ResourceStates) -> CallRet {
    use crate::execute::io_utils::receive_line;
    let call_ret = CallRet {
        call_index: 0,
        raw: Some(serialize_call_ret(ret, resource_states).unwrap()),
        ir: vec![],
        static_ret: false,
        unwritable_ret: false,
        init_arg: false,
        partial_opaque_ret: false,
    };
    let out = call_ret.serialize().unwrap();
    println!("ir: {out:?}");
    let ret_ir: CallRet = receive_line(&mut out.as_bytes()).unwrap();
    ret_ir
}

#[test]
fn test_serde_callret() {
    use crate::test;
    let mut resource_states = ResourceStates::default();
    let val = Box::new(0_u64) as FuzzObject;
    let ret = convert_ret_to_ir(&val, &resource_states);
    println!("val: {:?}, ir: {:?}", val, ret.ir);
    assert_eq!(ret.ir.len(), 1);
    assert_eq!(ret.ir[0].fields.len(), 0);
    assert_eq!(
        ret.ir[0].value.serialize().unwrap(),
        val.serialize().unwrap()
    );

    let val = Box::new(test::create_test_ptr()) as FuzzObject;
    let inner_fields = vec![
        FieldKey::Pointer,
        FieldKey::Field("p".to_string()),
        FieldKey::Pointer,
    ];
    resource_states.insert_ptr_size(val.get_ptr_by_keys(&[]).unwrap(), 1);
    resource_states.insert_ptr_size(val.get_ptr_by_keys(&inner_fields).unwrap(), 10);
    let ret = convert_ret_to_ir(&val, &resource_states);
    for (i, ir) in ret.ir.iter().enumerate() {
        println!("ir-{}: {:?}", i, ir.fields)
    }
    println!("{:?}", ret.ir[0].value);
    assert_eq!(ret.ir.len(), 3);
    assert_eq!(
        val.get_ptr_by_keys(&ret.ir[2].fields.list).unwrap(),
        val.get_ptr_by_keys(&inner_fields).unwrap()
    );
}
