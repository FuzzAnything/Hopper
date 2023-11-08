use std::{borrow::BorrowMut, collections::HashMap};

use eyre::ContextCompat;

use crate::{fuzz::*, fuzzer::Fuzzer, runtime::*, utils, BucketType};

/// Effective argument: a slice of statments
pub struct EffectiveArg {
    pub program_id: usize,
    pub stmt_index: usize,
    pub stmts: Vec<IndexedStmt>,
    pub hash: u64,
}

/// Buf's content and location
#[derive(Debug, Clone)]
pub struct EffectiveBuf {
    pub program_id: usize,
    pub stmt_index: usize,
    pub buf: Vec<u8>,
    pub hash: u64,
}

#[derive(Default)]
pub struct EffectiveList {
    pub arg_list: HashMap<String, Vec<EffectiveArg>>,
    pub buf_list: HashMap<String, Vec<EffectiveBuf>>,
}

use std::cell::RefCell;

thread_local! {
    pub static EFFECT: RefCell<EffectiveList> = RefCell::new(EffectiveList::default());
}

impl Fuzzer {
    /// Collect effective arguments from interesting seed programs
    pub fn collect_effective_args(
        &mut self,
        program: &FuzzProgram,
        new_edges: &[(usize, BucketType)],
    ) -> eyre::Result<()> {
        if !crate::config::ENABLE_EFF_ARG {
            return Ok(());
        }
        if program.ops.is_empty() {
            // view target call is effective in generated program
            let target_index = program.get_target_index().context("has target")?;
            Self::collect_effective_args_in_call(program, target_index)?;
            return Ok(());
        }
        // For mutated program, we need to locate which call is effective,
        let mut p = program.clone();
        // check ops again
        p.ops = program.ops.clone_with_program(&mut p);
        if p.ops.is_empty() {
            return Ok(());
        }
        let track_calls = p.get_track_calls();
        p.set_calls_track_cov(false);
        // find which call is effective
        for i in 0..p.stmts.len() {
            if !p.stmts[i].stmt.is_call() {
                continue;
            }
            if !track_calls.contains(&p.stmts[i].index.get_uniq()) {
                continue;
            }
            crate::log!(trace, "call {i} is trackable, check if it is effective");
            // only set current call trackable
            if let FuzzStmt::Call(call) = &mut p.stmts[i].stmt {
                call.track_cov = true;
            }
            let status = self.executor.execute_program(&p)?;
            // if it trigger the new edges, the call is effective
            if status.is_normal() && self.observer.feedback.path.contain_any(new_edges) {
                // effective call
                Self::collect_effective_args_in_call(&p, i)?;
            }
            if let FuzzStmt::Call(call) = &mut p.stmts[i].stmt {
                call.track_cov = false;
            }
        }
        Ok(())
    }

    /// Collect argument in effective call
    pub fn collect_effective_args_in_call(
        program: &FuzzProgram,
        call_i: usize,
    ) -> eyre::Result<()> {
        crate::log!(trace, "try to collect effective args in call {call_i}");
        if let FuzzStmt::Call(call) = &program.stmts[call_i].stmt {
            for (arg_pos, arg) in call.args.iter().enumerate() {
                let arg_index = arg.get();
                let p = slice_arg(program, call, call_i, arg_index)?;
                // if the arg is not effective
                // 1. the slice is not mutated by any ops or too long
                // 2. the arg is not mutated by relative calls
                if p.ops.is_empty() || p.stmts.len() > 12 {
                    continue;
                }
                if program.ops.iter().any(|op| {
                    // or call op that mutate arg
                    let ret = match &op.op {
                        MutateOperation::CallArg {
                            arg_pos: arg_i,
                            rng_state: _,
                        } => *arg_i == arg_pos,
                        MutateOperation::CallRelatedInsert {
                            f_name: _,
                            arg_pos: arg_i,
                            rng_state: _,
                        } => *arg_i == arg_pos,
                        _ => false,
                    };
                    ret && (op.key.get_index().unwrap().get() == call_i)
                }) {
                    crate::log!(
                        trace,
                        "ops do not mutate arg {arg_pos}, ops: {}!",
                        program.ops.serialize().unwrap()
                    );
                    continue;
                }
                crate::log!(trace, "sliced: {}", p.serialize_all()?);
                crate::log!(trace, "arg_pos {arg_pos} is effective!");
                let arg_ident = call.fg.arg_idents[arg_pos];
                let arg_type = call.fg.arg_types[arg_pos];
                let arg_alias_type = call.fg.alias_arg_types[arg_pos];
                // null pointer
                if utils::is_pointer_type(arg_type) && p.stmts.len() == 1 {
                    continue;
                }
                EFFECT.with::<_, eyre::Result<bool>>(|eff| {
                    let mut eff = eff.borrow_mut();
                    let _ = eff.collect_effective_buf(program, arg_index)?
                        || eff.collect_effective_arg(
                            p.stmts,
                            program.id,
                            arg_index,
                            arg_ident,
                            arg_alias_type,
                        )?;
                    Ok(true)
                })?;
            }
        }
        Ok(())
    }
}

impl CallStmt {
    /// Set effective argument in call's i-th argument
    pub fn set_effective_ith_call_arg(
        &mut self,
        program: &mut FuzzProgram,
        arg_pos: usize,
        depth: usize,
    ) -> eyre::Result<Option<usize>> {
        if depth > crate::config::MAX_DEPTH || program.stmts.len() > crate::config::MAX_STMTS_LEN {
            return Ok(None);
        }
        let arg_ident = self.fg.arg_idents[arg_pos];
        let arg_alias_type = self.fg.alias_arg_types[arg_pos];
        let key = format!("{arg_ident}_{arg_alias_type}");
        // insert offset
        let mut last_insert = if let Some(stub_i) = program.get_stub_stmt_index() {
            stub_i.get()
        } else {
            program.stmts.len()
        };
        // slice previous arg
        let prev_slice = slice_arg(program, self, last_insert, self.args[arg_pos].get())?;
        let choosed_arg = EFFECT.with(|eff| {
            eff.borrow()
                .choose_effective_arg(program, &prev_slice.stmts, &key)
        });
        if let Some((eff_i, stmts)) = choosed_arg {
            // crate::log!(trace, "program: {}", program.serialize()?);
            crate::log!(
                trace,
                "use effective arg-{eff_i}: {}",
                stmts.serialize().unwrap()
            );
            // hold stmt unit loop finish, to avoid the `skip` ones change the ref-count.
            for is in stmts.iter().rev() {
                let p_is = is.clone_with_program(program);
                crate::log!(trace, "p: {}", p_is.serialize()?);
                // if they have the same uniq id and type
                // we try to replace it
                let mut existing = None;
                let index_uniq = is.index.get_uniq();
                for pis in program.stmts.iter_mut() {
                    if pis.stmt.is_stub() || pis.index.get() >= last_insert {
                        break;
                    }
                    if pis.index.get_uniq() == index_uniq {
                        existing = Some(pis);
                    }
                }
                if let Some(existing) = existing {
                    crate::log!(
                        trace,
                        "replace {} with {}",
                        existing.index.get(),
                        is.index.get()
                    );
                    let _ = std::mem::replace(&mut existing.stmt, p_is.stmt);
                    let new_insert = existing.index.get();
                    eyre::ensure!(new_insert < last_insert, "insert order is wrong!");
                    last_insert = new_insert;
                    continue;
                }
                // should clone again
                match &is.stmt {
                    // argument
                    FuzzStmt::Load(_load) => {
                        if is.index.get_ref_used() == 1 {
                            crate::log!(trace, "set arg index: {}", is.index.get());
                            self.args[arg_pos] = p_is.index.use_index();
                        }
                    }
                    // if the context call exists, we skip it
                    FuzzStmt::Call(call) => {
                        // ref <=1 : the context is for our target call
                        if is.index.get_ref_used() <= 1 && call.is_implicit() {
                            if self.has_implicit_context(program, call.fg.f_name) {
                                crate::log!(trace, "ignore dup implicit context");
                                // continue;
                            }
                            // otherwise, we add it to the ctx
                            self.contexts.push(is.index.use_index());
                        }
                        // check if duplicated relative call before
                        if self.has_relative_context(program, call.fg.f_name) {
                            crate::log!(trace, "ignore dup relative context");
                            // continue;
                        }
                    }
                    _ => {}
                }
                program.stmts.insert(last_insert, p_is);
                program.resort_indices();
            }
            program.tmp_indices.clear();
            crate::log!(trace, "new: {}", program.serialize()?);
            program.check_ref_use()?;
            crate::log!(trace, "use effective arg done");
            return Ok(Some(eff_i));
        }
        crate::log!(trace, "fail to find eff arg for {key}");
        Ok(None)
    }
}

impl EffectiveList {
    pub fn choose_effective_arg(
        &self,
        program: &mut FuzzProgram,
        slice: &[IndexedStmt],
        key: &str,
    ) -> Option<(usize, Vec<IndexedStmt>)> {
        if let Some(list) = self.arg_list.get(key) {
            crate::log!(trace, "found {} effective args for `{}`", list.len(), key);
            // crate::log!(trace, "slice: {}", slice.serialize().unwrap());
            let slice_hash = utils::hash_buf(slice.serialize().unwrap().as_bytes());
            if let Some((i, arg)) = rng::choose_iter(
                list.iter()
                    .enumerate()
                    .filter(|(_, ea)| ea.program_id != program.id && ea.hash != slice_hash),
            ) {
                let mut stmts: Vec<IndexedStmt> = vec![];
                let mut slice_len = slice.len();
                let mut holder = FuzzProgram::default();
                // clone arg slice and avoid the same index uniq
                for is in arg.stmts.iter().rev() {
                    let mut is = is.clone_with_program(&mut holder);
                    // avoid they have the same uniq
                    if program.get_mut_stmt_by_index_uniq(&is.index).is_some() {
                        is.index.reset_uniq();
                    }
                    // crate::log!(trace, "arg stmt: {}", is.serialize().unwrap());
                    // if they are likely to the same and used by multiple ref
                    // we set the same index uniq
                    if let FuzzStmt::Load(load) = &is.stmt {
                        if load.state.pointer.is_some() && slice_len > 0 {
                            let ident = load.get_ident();
                            let ty = load.value.type_name();
                            let iter = slice[..slice_len].iter().filter_map(|slice_is| {
                                if let FuzzStmt::Load(load) = &slice_is.stmt {
                                    if ident == load.get_ident() && ty == load.value.type_name() {
                                        let index = &slice_is.index;
                                        if let Some(p_is) = program.get_stmt_by_index_uniq(index) {
                                            //  && stmts.iter().all(|s| s.index.get_uniq() != index.get_uniq())
                                            if p_is.index.get_ref_used() > 2 {
                                                return Some(index.use_index());
                                            }
                                        }
                                    }
                                }
                                None
                            });
                            if let Some(index) = rng::choose_iter(iter) {
                                crate::log!(trace, "update uniq for : {}", index.get());
                                slice_len = index.get();
                                is.index.borrow_mut().set_uniq(index.get_uniq());
                            }
                        }
                    }
                    stmts.push(is);
                }
                stmts.reverse();
                return Some((i, stmts));
            }
        }
        None
    }

    pub fn collect_effective_arg(
        &mut self,
        slice_stmts: Vec<IndexedStmt>,
        program_id: usize,
        stmt_index: usize,
        arg_ident: &str,
        arg_type: &str,
    ) -> eyre::Result<bool> {
        let buf = slice_stmts.serialize()?;
        let hash = utils::hash_buf(buf.as_bytes());
        let arg = EffectiveArg {
            program_id,
            stmt_index,
            stmts: slice_stmts,
            hash,
        };
        let key = format!("{arg_ident}_{arg_type}",);
        crate::log!(trace, "new effective arg in `{}`: {}", key, buf);
        if let Some(list) = self.arg_list.get_mut(&key) {
            if list.iter().all(|s| s.hash != hash) {
                // only keep 5 newest effective arguments
                if list.len() >= 5 {
                    list.remove(0);
                }
                list.push(arg);
            }
        } else {
            let list = vec![arg];
            self.arg_list.insert(key.to_string(), list);
        }
        Ok(true)
    }

    fn collect_effective_buf(&mut self, program: &FuzzProgram, arg_i: usize) -> eyre::Result<bool> {
        if let FuzzStmt::Load(load) = &program.stmts[arg_i].stmt {
            if load.state.pointer.is_none() {
                return Ok(false);
            }
            let ptr_loc = &load.state.pointer.as_ref().unwrap().pointer_location;
            if !ptr_loc.is_null()
                && (ptr_loc.fields.is_empty()
                    || (ptr_loc.fields.len() == 1 && ptr_loc.fields.list[0] == FieldKey::Pointer))
            {
                let is = &program.stmts[ptr_loc.get_index()?.get()];
                if let Some((value, ident, is_u8)) = get_buf_value(&is.stmt) {
                    let key = if is_u8 {
                        format!("{ident}_u8")
                    } else {
                        format!("{ident}_i8")
                    };
                    let buf = cast_bytes(value.as_ref(), is_u8)?.to_vec();
                    let hash = utils::hash_buf(&buf);
                    let eff_buf = EffectiveBuf {
                        program_id: program.id,
                        stmt_index: is.index.get(),
                        buf,
                        hash,
                    };
                    crate::log!(
                        trace,
                        "save buf at program {} stmt {} to {key}, hash: {hash}",
                        eff_buf.program_id,
                        eff_buf.stmt_index
                    );
                    if let Some(list) = self.buf_list.get_mut(&key) {
                        if list.iter().all(|s| s.hash != hash) {
                            list.push(eff_buf);
                        }
                    } else {
                        let list = vec![eff_buf];
                        self.buf_list.insert(key, list);
                    }
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

fn get_buf_value(stmt: &FuzzStmt) -> Option<(&FuzzObject, &str, bool)> {
    match stmt {
        FuzzStmt::Load(load) => {
            let type_name = load.value.type_name();
            let u8_vec = type_name == "alloc::vec::Vec<u8>";
            let i8_vec = type_name == "alloc::vec::Vec<i8>";
            if u8_vec || i8_vec {
                return Some((&load.value, load.get_ident(), u8_vec));
            }
        }
        // Now we do not use it because we move check_effective before review
        FuzzStmt::Call(call) => {
            if let Some(ret_type) = call.fg.ret_type {
                if let Some(inner_type) = utils::get_pointer_inner(ret_type) {
                    let is_u8 = inner_type == "u8";
                    let is_i8 = inner_type == "i8";
                    if is_u8 || is_i8 {
                        // crate::log!(trace, "get buf from call: {call:?}");
                        // ret's layout
                        // { {field: [], value: ptr}, {field: [Pointer], value: Vec<T>}
                        if call.ret_ir.len() == 2 {
                            let ret_val = &call.ret_ir[1];
                            // ret_val.fields.as_slice() == &[FieldKey::Pointer]
                            return Some((&ret_val.value, &call.ident, is_u8));
                        }
                    }
                }
            }
        }
        _ => {}
    }
    None
}

fn cast_bytes(value: &dyn ObjFuzzable, is_u8: bool) -> eyre::Result<&[u8]> {
    if is_u8 {
        Ok(value.downcast_ref::<Vec<u8>>().context("downcast buf")?)
    } else {
        let buf = value.downcast_ref::<Vec<i8>>().context("downcast buf")?;
        let u8_buf = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len()) };
        Ok(u8_buf)
    }
}

pub fn slice_arg(
    program: &FuzzProgram,
    call: &CallStmt,
    call_i: usize,
    arg_i: usize,
) -> eyre::Result<FuzzProgram> {
    crate::log!(trace, "slice arg {arg_i} at call {call_i}");
    let mut p = program.clone();
    p.stmts.truncate(call_i);
    let index = p.stmts[arg_i].index.use_index();
    // if the calls are related to `arg`
    let mut ctxs = vec![];
    for ctx in &call.contexts {
        if let FuzzStmt::Call(call) = &p.stmts[ctx.get()].stmt {
            if call.args.contains(&index) {
                ctxs.push(ctx.clone_with_program(&mut p));
            }
        }
    }

    // crate::log!(trace, "ctxs for slice: {:?}", ctxs);
    // check ref use will remove statements that do not related to `index`
    p.check_ref_use()?;

    // remove those unrelated calls
    {
        let mut removed = false;
        let mut used_indices = get_relative_indices_recusively(&p, vec![index.use_index()]);
        for i in (0..p.stmts.len()).rev() {
            let is = &p.stmts[i];
            if let FuzzStmt::Call(call) = &is.stmt {
                let used = get_relative_indices_recusively(&p, call.args.clone());
                if call.is_relative() && used.iter().all(|uniq| !used_indices.contains(uniq)) {
                    p.delete_stmt(i);
                    removed = true;
                    continue;
                }
                for uniq in used {
                    if !used_indices.contains(&uniq) {
                        used_indices.push(uniq);
                    }
                }
            }
        }
        if removed {
            crate::log!(trace, "remove some unrelated calls, check ref again!");
            p.check_ref_use()?;
        }
    }

    // move ctxs to last
    for ctx in ctxs {
        let stmt = p.stmts.remove(ctx.get());
        p.stmts.push(stmt);
        p.resort_indices();
    }
    p.ops = program.ops.clone_with_program(&mut p);
    // remove those useless ops
    p.ops.retain(|o| !o.key.is_released());
    Ok(p)
}

/// Get relative indices that used by the list of stmts recursively
fn get_relative_indices_recusively(program: &FuzzProgram, mut list: Vec<StmtIndex>) -> Vec<u64> {
    let mut used: Vec<u64> = vec![];
    while let Some(i) = list.pop() {
        if let Some(is) = program.get_stmt_by_index_uniq(&i) {
            if let FuzzStmt::Load(load) = &is.stmt {
                let _ = load.state.find_any_stmt_in_state_with(|index| {
                    list.push(index.use_index());
                    // to visit all
                    false
                });
            }
        }
        used.push(i.get_uniq());
    }
    used
}

pub fn save_effective_args() -> eyre::Result<()> {
    use std::io::Write;
    EFFECT.with(|eff| {
        let eff = eff.borrow();
        let path = crate::config::output_file_path("misc/eff_arg.json");
        let mut f = std::fs::File::create(path)?;
        for args in &eff.arg_list {
            writeln!(f, "***********************************")?;
            writeln!(f, "KEY: {}", args.0)?;
            writeln!(f, "***********************************")?;
            for arg in args.1 {
                writeln!(
                    f,
                    "ID: {}, Index: {}, Hash: {}",
                    arg.program_id, arg.stmt_index, arg.hash
                )?;
                for stmt in &arg.stmts {
                    write!(f, "{}", stmt.serialize()?)?;
                }
                writeln!(f, "------------------------------------")?;
            }
        }

        let path = crate::config::output_file_path("misc/eff_buf.json");
        let mut f = std::fs::File::create(path)?;
        for args in &eff.buf_list {
            writeln!(f, "***********************************")?;
            writeln!(f, "KEY: {}", args.0)?;
            writeln!(f, "***********************************")?;
            for arg in args.1 {
                writeln!(
                    f,
                    "ID: {}, Index: {}, Hash: {}",
                    arg.program_id, arg.stmt_index, arg.hash
                )?;
                f.write_all(&arg.buf)?;
                writeln!(f, "\n------------------------------------")?;
            }
        }
        Ok(())
    })
}

pub fn load_effective_args() -> eyre::Result<()> {
    use std::io::BufRead;
    let path = crate::config::output_file_path("misc/eff_arg.json");
    if !path.exists() {
        return Ok(());
    }
    EFFECT.with(|eff| {
        let mut eff = eff.borrow_mut();
        let buf = std::fs::read(path)?;
        let mut key = "".to_string();
        let mut program = FuzzProgram::default();
        let mut id: usize = 0;
        let mut index: usize = 0;
        let mut hash: u64 = 0;
        for line in buf.lines() {
            let line = line?;
            if line.is_empty() || line.starts_with("****") {
                continue;
            }
            if let Some(found_key) = line.strip_prefix("KEY: ") {
                key = found_key.trim().to_string();
                eff.arg_list.insert(key.clone(), vec![]);
                continue;
            }
            let mut de = Deserializer::new(&line, Some(&mut program));
            if de.strip_token("ID: ") {
                id = de.parse_number()?;
                de.eat_token(", Index: ")?;
                index = de.parse_number()?;
                de.eat_token(", Hash: ")?;
                hash = de.parse_number()?;
                continue;
            }
            de.canary = false;
            if de.strip_token("------") {
                let stmts = std::mem::take(&mut program.stmts);
                program.clear_tmp_indices()?;
                program.stmts.clear();
                if let Some(list) = eff.arg_list.get_mut(&key) {
                    let arg = EffectiveArg {
                        program_id: id,
                        stmt_index: index,
                        stmts,
                        hash,
                    };
                    list.push(arg);
                }
                // crate::log!(trace, "add new arg");
                continue;
            }
            // crate::log!(trace, "line: {}", de.buf);
            if de.strip_token("vec(") {
                let _ = de.next_token_until("[");
            }
            if de.strip_token(", ") {
                continue;
            }
            let is = IndexedStmt::deserialize(&mut de)?;
            program.stmts.push(is);
        }
        Ok(())
    })
}

#[test]
fn test_effective_num() {
    use crate::test;
    let arg_ident = "a";
    let arg_type = "u8";
    let mut tmp_p = FuzzProgram::default();
    let arg = test::generate_load_stmt::<u8>(arg_ident, arg_type);
    let arg_val = arg.serialize().unwrap();
    tmp_p.append_stmt(arg);
    println!("*arg: {}", tmp_p.serialize().unwrap());
    EFFECT.with(|eff| {
        eff.borrow_mut()
            .collect_effective_arg(tmp_p.stmts, 1, 0, arg_ident, arg_type)
            .unwrap();
    });
    let mut call_p = FuzzProgram::generate_program_for_func("func_add").unwrap();
    println!("*before: {}", call_p.serialize().unwrap());
    if let FuzzStmt::Call(mut call) = call_p.stmts.last_mut().unwrap().stmt.lend() {
        call.set_effective_ith_call_arg(&mut call_p, 0, 0).unwrap();
    }

    println!("*set: {}", call_p.serialize().unwrap());
    assert!(
        call_p.stmts[0].stmt.serialize().unwrap() == arg_val
            || call_p.stmts[1].stmt.serialize().unwrap() == arg_val
    );
}

#[test]
fn test_effective_pointer() {
    let arg_ident = "ptr";
    let arg_type = utils::pointer_type("u8", true);
    let mut tmp_p = FuzzProgram::default();
    flag::set_pilot_det(true);
    let arg = LoadStmt::generate_new(&mut tmp_p, &arg_type, arg_ident, 0).unwrap();
    flag::set_pilot_det(false);
    let arg_val = tmp_p.stmts[0].stmt.serialize().unwrap();
    tmp_p.append_stmt(arg);
    println!("arg: {}", tmp_p.serialize().unwrap());
    EFFECT.with(|eff| {
        eff.borrow_mut()
            .collect_effective_arg(tmp_p.stmts, 1, 0, arg_ident, &arg_type)
            .unwrap();
    });
    let mut call_p = FuzzProgram::generate_program_for_func("test_arr").unwrap();
    println!("p: {}", call_p.serialize().unwrap());
    if let FuzzStmt::Call(mut call) = call_p.stmts.last_mut().unwrap().stmt.lend() {
        println!("try effective arg");
        call.set_effective_ith_call_arg(&mut call_p, 0, 0).unwrap();
    }

    println!("set: {}", call_p.serialize().unwrap());

    assert!(
        call_p.stmts[0].stmt.serialize().unwrap() == arg_val
            || call_p.stmts[1].stmt.serialize().unwrap() == arg_val
    );

    println!("test multiple ref case");
    // multiple ref argument
    let mut call_p = FuzzProgram::generate_program_for_func("test_arr").unwrap();
    let mut call_p2 = FuzzProgram::generate_program_for_func("test_arr").unwrap();
    let index = call_p.stmts.len() - 1;
    if let FuzzStmt::Call(call) = &mut call_p2.stmts.last_mut().unwrap().stmt {
        call.args[0] = call_p.get_target_stmt().unwrap().args[0].use_index();
    }
    for is in call_p2.stmts {
        call_p.stmts.push(is);
    }
    call_p.resort_indices();
    // call_p.check_ref_use();
    println!("new call_p: {}", call_p.serialize().unwrap());
    if let FuzzStmt::Call(mut call) = call_p.stmts[index].stmt.lend() {
        println!("try effective arg");
        call.set_effective_ith_call_arg(&mut call_p, 0, 0).unwrap();
        println!("call: {}", call.serialize().unwrap());
        let _index = call_p.withdraw_stmt(FuzzStmt::Call(call)).unwrap();
    }
    println!("new set: {}", call_p.serialize().unwrap());

    assert_eq!(call_p.get_target_stmt().unwrap().args[0].get_ref_used(), 3)
}
