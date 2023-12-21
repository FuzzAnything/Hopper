//! Generate and mutate pointers
//! Including:
//!   - assign a location for pointer during generation
//!   - mutate existing pointer to a new location

use super::*;
use crate::{config, runtime::*, utils};
use eyre::ContextCompat;

// static mut str_cache: Vec<&'static str> = vec![];
/// Mutate specific pointer's location
pub fn mutate_pointer_location(
    program: &mut FuzzProgram,
    root_state: &mut ObjectState,
    keys: &[FieldKey],
) -> eyre::Result<MutateOperation> {
    let state = root_state.get_child_mut_by_fields(keys)?;
    let depth = program.get_stub_stmt_depth()?;
    let op = set_pointer_location(program, state, depth, false)?;
    Ok(op)
}

/// Generate all pointer inside state
pub fn generate_pointer_location(
    program: &mut FuzzProgram,
    state: &mut ObjectState,
    depth: usize,
) -> eyre::Result<()> {
    // Ignore state inside option, e.g. function pointer
    if state.key == FieldKey::Option {
        return Ok(());
    }
    if let Some(ps) = state.pointer.as_ref() {
        if ps.pointer_location.is_null() {
            let _ = set_pointer_location(program, state, depth, true)?;
        }
    }
    if state.children.len() <= crate::config::MAX_VEC_LEN {
        for sub_state in state.children.iter_mut() {
            generate_pointer_location(program, sub_state, depth)?;
        }
    }
    Ok(())
}

/// Mutate specific pointer's location with specific operation
pub fn mutate_pointer_location_by_op(
    program: &mut FuzzProgram,
    root_state: &mut ObjectState,
    mut keys: &[FieldKey],
    op: &MutateOperation,
) -> eyre::Result<()> {
    if keys.last().map_or(false, |k| k.is_union_root()) {
        keys = &keys[..keys.len() - 1];
    }
    let state = root_state.get_child_mut_by_fields(keys)?;
    match op {
        MutateOperation::PointerNull => {
            state.get_pointer_mut()?.pointer_location = Location::null();
        }
        MutateOperation::PointerUse { loc } => {
            let mut loc = loc.use_loc();
            // stmt in loc may not 'refer' to a stmt in current program, e.g create by `dup`
            // so we update it to the index of program's stmt here
            if let Some(index) = loc.stmt_index.as_mut() {
                let is = program
                    .get_stmt_by_index_uniq(index)
                    .with_context(|| format!("can't find stmt with uniq: {index:?}"))?;
                *index = is.index.use_index();
            }
            state.get_pointer_mut()?.pointer_location = loc;
        }
        MutateOperation::PointerRet { f_name, rng_state } => {
            let ident = state.key.as_str()?;
            let depth = program.get_stub_stmt_depth()?;
            let _tmp_rng = rng::TempRngGuard::temp_use(rng_state);
            let loc = create_call_stmt_for_ptr(program, ident, f_name, depth)?;
            state.get_pointer_mut()?.pointer_location = loc;
        }
        MutateOperation::PointerGen { rng_state } => {
            let _tmp_rng = rng::TempRngGuard::temp_use(rng_state);
            let loc = create_load_stmt_for_ptr_wrap(program, state)?;
            if loc.is_null() {
                set_incomplete_gen(true);
            }
            state.get_pointer_mut()?.pointer_location = loc;
        }
        MutateOperation::PointerGenChar => {
            state.pointer.as_mut().context("has ptr")?.pointer_type = "i8";
            let loc = create_load_stmt_for_ptr_wrap(program, state)?;
            state.get_pointer_mut()?.pointer_location = loc;
        }
        MutateOperation::PointerCast {
            cast_type,
            rng_state,
        } => {
            if !state.get_pointer()?.pointer_location.is_null() {
                return Ok(());
            }
            let depth = program.get_stub_stmt_depth()?;
            let _tmp_rng = rng::TempRngGuard::temp_use(rng_state);
            let use_null = use_null_or_not(program, state.parent.is_none(), depth, false);
            if use_null {
                crate::log_trace!("use null pointer");
                return Ok(());
            }
            if let Some(ty) = utils::get_pointer_inner(cast_type) {
                state.pointer.as_mut().context("has ptr")?.pointer_type = utils::get_static_ty(ty);
                let loc = create_load_stmt_for_ptr_wrap(program, state)?;
                state.get_pointer_mut()?.pointer_location = loc;
            };
        }
        MutateOperation::InitOpaque { call_i } => {
            let depth = program.get_stub_stmt_depth()?;
            let op = init_opaque_pointer(program, state, *call_i, depth)?;
            if op.is_nop() {
                set_incomplete_gen(true);
            }
        }
        MutateOperation::InitOpaqueForInfer { call_i } => {
            let depth = program.get_stub_stmt_depth()?;
            let op = init_opaque_pointer(program, state, *call_i, depth)?;
            if op.is_nop() {
                set_incomplete_gen(true);
            } else {
                // the op is derived to be another operation (more detailed)
                program.ops.push(state.as_mutate_operator(op));
            }
        }
        MutateOperation::RemoveInitOpaque => {
            if let Some(cur_index) = program.get_stub_stmt_index() {
                if let Some(call_index) = program.has_been_inited(&cur_index) {
                    // if program.check_call_related_to_stmt(cur_index.get(), call_index) {
                    program.stmts.remove(call_index);
                }
            }
        }
        MutateOperation::PointerCanary => {
            let depth = program.get_stub_stmt_depth()?;
            let load_stmt = LoadStmt::generate_vec(program, "i8", "mock_canary", depth + 1)?;
            let len = load_stmt.value.get_length();
            let stmt_index = program.insert_or_append_stmt(load_stmt)?;
            let loc = Location::new(stmt_index, LocFields::new(vec![FieldKey::Index(len + 1)]));
            state.get_pointer_mut()?.pointer_location = loc;
        }
        MutateOperation::PointerFile { read } => {
            // generate a file, and point to it.
            let ident = state.key.as_str()?;
            let depth = program.get_stub_stmt_depth()?;
            let file_stmt = FileStmt::generate_new(program, ident, false, false, *read, depth)?;
            let stmt_index = program.insert_or_append_stmt(file_stmt)?;
            let loc = Location::new(stmt_index, LocFields::new(vec![FieldKey::Pointer]));
            state.get_pointer_mut()?.pointer_location = loc;
        }
        MutateOperation::VecPad { .. } | MutateOperation::BufRefine { .. } => {
            let loc = &state.get_pointer()?.pointer_location;
            let is_null = loc.is_null();
            let is_returned = loc.stmt_index.as_ref().map_or(false, |ptee| {
                if let FuzzStmt::Call(..) = &program.stmts[ptee.get()].stmt {
                    return true;
                }
                false
            });

            // If the vec/buffer is loaded from a call statement,
            // we replace it with a load statement that is adhere to the constriant.
            if is_null || is_returned {
                let loc: Location = create_load_stmt_for_ptr_wrap(program, state)?;
                if loc.is_null() {
                    return Ok(());
                }
                state.get_pointer_mut()?.pointer_location = loc;
            }
            let loc = &state.get_pointer()?.pointer_location;
            if let FuzzStmt::Load(load) = &mut program.stmts[loc.get_index()?.get()].stmt {
                // if the pointee is not a vector, we create a vector for it.
                if utils::is_vec_type(load.value.type_name()) {
                    load.value.mutate_by_op(&mut load.state, &[], op)?;
                } else {
                    let loc: Location = create_load_stmt_for_ptr_wrap(program, state)?;
                    if !loc.is_null() {
                        if let FuzzStmt::Load(load) =
                            &mut program.stmts[loc.get_index()?.get()].stmt
                        {
                            load.value.mutate_by_op(&mut load.state, &[], op)?;
                        }
                        state.get_pointer_mut()?.pointer_location = loc;
                    }
                }
            }
        }
        MutateOperation::UnionUse { rng_state, member } => {
            // If the target member is a pointer, we intercept the mutate operation here to set the pointer location.
            // Otherwise, the mutation is completed later by the object itself.

            // If the target member is already set, don't do anything
            let sub_state = state.last_child_mut()?;
            // If this is a pointer pointing to another union
            if let FieldKey::Field(f) = &sub_state.key {
                if f == member {
                    flag::set_refine_suc(false);
                    return Ok(());
                }
            }
            let fields_ty = global_gadgets::get_instance()
                .get_object_builder(state.ty)?
                .get_fields_ty();

            if let Some(type_name) = fields_ty.get(member) {
                if utils::is_pointer_type(type_name) {
                    let is_null = state
                        .pointer
                        .as_ref()
                        .map_or(false, |ps| ps.pointer_location.is_null());
                    state.clear();
                    let sub_state = state
                        .add_child(member.as_str(), utils::get_static_ty(type_name))
                        .last_child_mut()?;
                    let is_mut = utils::is_mut_pointer_type(type_name);
                    if is_null {
                        sub_state.pointer = Some(PointerState::new_pointer(
                            Location::null(),
                            utils::get_static_ty(utils::get_pointer_inner(type_name).unwrap()),
                            is_mut,
                        ))
                    } else {
                        let ident = sub_state.key.as_str()?;
                        let is_opaque = utils::is_opaque_type(type_name);
                        let depth = program.get_stub_stmt_depth()?;
                        let inner_type = utils::get_pointer_inner(type_name).unwrap();
                        let _tmp_rng = rng::TempRngGuard::temp_use(rng_state);
                        let loc =
                            create_load_stmt_for_ptr(program, inner_type, ident, is_opaque, depth)?;
                        let pt_type_holder = global_gadgets::get_instance()
                            .types
                            .keys()
                            .find(|s| s == &inner_type);
                        if let Some(pt_type) = pt_type_holder {
                            sub_state.pointer =
                                Some(PointerState::new_pointer(loc, pt_type, is_mut));
                            return Ok(());
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

macro_rules! impl_fuzz_pointer {
    ($pointer:ident, $name:literal, $is_mut:tt) => {
        impl<T: ObjGenerate + ObjFuzzable + ObjectDeserialize> ObjGenerate for $pointer<T> {
            fn generate_new(state: &mut ObjectState) -> eyre::Result<Self> {
                // generate later
                Ok(Self::null(state))
            }
        }

        impl<T: ObjFuzzable> ObjMutate for $pointer<T> {
            fn mutate(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
                if rng::unlikely() && !crate::is_input_only() {
                    Ok(state.as_mutate_operator(MutateOperation::PointerTodo))
                } else {
                    Ok(state.as_mutate_operator(MutateOperation::Nop))
                }
            }

            fn mutate_by_op(
                &mut self,
                _state: &mut ObjectState,
                keys: &[FieldKey],
                _op: &MutateOperation,
            ) -> eyre::Result<()> {
                if keys.is_empty() {
                    flag::set_mutate_ptr(true);
                }
                // special case for union
                if keys.len() == 1 && keys.last().map_or(false, |k| k.is_union_root()) {
                    flag::set_mutate_ptr(true);
                }
                Ok(())
            }
        }
    };
}

impl_fuzz_pointer!(FuzzMutPointer, "mut", true);
impl_fuzz_pointer!(FuzzConstPointer, "const", false);

impl<T> ObjMutate for FuzzFrozenPointer<T> {
    fn mutate(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        crate::log!(trace, "it is a frozen pointer, do not mutated!");
        Ok(state.as_mutate_operator(MutateOperation::Nop))
    }

    fn mutate_by_op(
        &mut self,
        _state: &mut ObjectState,
        _keys: &[FieldKey],
        _op: &MutateOperation,
    ) -> eyre::Result<()> {
        Ok(())
    }
}

impl<T> ObjGenerate for FuzzFrozenPointer<T> {
    fn generate_new(state: &mut ObjectState) -> eyre::Result<Self> {
        let _ = state.replace_weight(0);
        Ok(Self::new())
    }
}

fn use_null_or_not(program: &FuzzProgram, is_root: bool, depth: usize, is_generate: bool) -> bool {
    // avoid reach deep depth
    if flag::is_pilot_det() {
        !is_root
            && (depth >= config::PILOT_MAX_DEPTH || program.stmts.len() > config::MAX_STMTS_LEN)
    } else if depth > config::MAX_DEPTH || program.stmts.len() > config::MAX_STMTS_LEN {
        true
    } else if is_generate {
        rng::mostly()
    } else if is_root || depth < config::PILOT_MAX_DEPTH {
        rng::coin()
    } else {
        rng::likely()
    }
}

/// Find a new location for pointers
fn set_pointer_location(
    program: &mut FuzzProgram,
    state: &mut ObjectState,
    depth: usize,
    is_generate: bool,
) -> eyre::Result<MutateOperation> {
    eyre::ensure!(depth < 50, "the program is too complex with huge depth!");
    let ident = state.key.as_str()?;
    let is_root = state.parent.is_none();
    let parent_ty_holder = state.get_parent().map(|p| p.ty);
    let ps = state.pointer.as_mut().context("pointer has ps")?;
    let type_name = ps.pointer_type;
    let is_opaque = utils::is_opaque_type(type_name);
    // once the pointer is mutated, stub is removed
    ps.stub = false;

    // 1. the pointer may be null
    let use_null = use_null_or_not(program, is_root, depth, is_generate);
    if use_null {
        crate::log_trace!("`{type_name}*`: use null pointer, depth: {depth}");
        ps.pointer_location = Location::null();
        return Ok(MutateOperation::PointerNull);
    }
    // 2. find existing call/load for pointer
    // since it may bring cases that a locations is used in multiple pointers,
    // and the pointers are in the same object or the functions(arguments),
    // which may causes crash.
    // thus, we only consider the statement itself (except elements inside statement) for reusing pointer.
    if is_root && flag::is_reuse_stmt() && rng::rarely() {
        if let Some(loc) = find_location_from_stmts(program, type_name, ident) {
            crate::log!(trace, "`{}*` use existing pointer", type_name);
            // dup loc to avoid ref-checking
            let loc_dup = loc.dup();
            ps.pointer_location = loc;
            return Ok(MutateOperation::PointerUse { loc: loc_dup });
        }
    }

    // 3. the pointer may be return from function
    // if it is a pointer in a root statement, it will use calls directly in call mutation
    if !is_root && flag::use_call(type_name, is_opaque, depth) {
        let ptr_type_name = utils::pointer_type(type_name, ps.is_mut);
        let alias_type_name =
            get_alias_type_name(program, 0, ident, &ptr_type_name, parent_ty_holder);
        if let Some(provider) = find_func_with_return_type(&ptr_type_name, alias_type_name) {
            let rng_state = rng::save_rng_state();
            // the arguments of call may lead to refence circle, so we do not reuse stmt
            let loc = create_call_stmt_for_ptr(program, ident, provider, depth)?;
            ps.pointer_location = loc;
            return Ok(MutateOperation::PointerRet {
                f_name: provider.to_string(),
                rng_state,
            });
        }
    }

    // 4. create a load for pointer
    crate::log!(trace, "load new value for pointer `{}*`", type_name);
    let rng_state = rng::save_rng_state();
    let loc = create_load_stmt_for_ptr(program, type_name, ident, is_opaque, depth)?;
    if loc.is_null() {
        return Ok(MutateOperation::PointerNull);
    }
    ps.pointer_location = loc;
    Ok(MutateOperation::PointerGen { rng_state })
}

/// Insert a new load statement, and return its location
fn create_load_stmt_for_ptr_wrap(
    program: &mut FuzzProgram,
    state: &ObjectState,
) -> eyre::Result<Location> {
    let ident = state.key.as_str()?;
    let depth = program.get_stub_stmt_depth()?;
    let type_name = state.pointer.as_ref().context("has ptr")?.pointer_type;
    let is_opaque = utils::is_opaque_type(type_name);
    create_load_stmt_for_ptr(program, type_name, ident, is_opaque, depth)
}

/// Insert a new load statement, and return its location
fn create_load_stmt_for_ptr(
    program: &mut FuzzProgram,
    type_name: &str,
    ident: &str,
    is_opaque: bool,
    depth: usize,
) -> eyre::Result<Location> {
    crate::log_trace!("create load for type: {type_name}");
    let load_stmt = if is_opaque {
        // do not mutate the opaque struct
        // LoadStmt::generate_constant(type_name, ident)?

        // do not load a opaque struct by ourself from scratch
        return Ok(Location::null());
    } else {
        LoadStmt::generate_vec(program, type_name, ident, depth + 1)?
    };
    let stmt_index = program.insert_or_append_stmt(load_stmt)?;
    Ok(Location::stmt(stmt_index))
}

/// Insert a new call statement, and return its location
fn create_call_stmt_for_ptr(
    program: &mut FuzzProgram,
    ident: &str,
    f_name: &str,
    depth: usize,
) -> eyre::Result<Location> {
    crate::log!(trace, "use call `{}` for pointer ", f_name);
    let _tmp = flag::ReuseStmtGuard::temp_disable();
    let call = CallStmt::generate_new(program, ident, f_name, depth + 1)?;
    let call_stmt = program.insert_or_append_stmt(call)?;
    let _ = program.insert_or_append_stmt(AssertStmt::assert_non_null(call_stmt.use_index()));
    let mut loc = Location::stmt(call_stmt);
    loc.fields.push(FieldKey::Pointer);
    Ok(loc)
}

/// Find location from exsiting statement
fn find_location_from_stmts(
    program: &FuzzProgram,
    type_name: &str,
    ident: &str,
) -> Option<Location> {
    // find ty, or alloc::vec::Vec<ty> / [ty: N]
    let mut loc_list = vec![];
    // let vec_ty = utils::vec_type(type_name);
    for indexed_stmt in program.stmts.iter() {
        if indexed_stmt.stmt.is_stub() {
            break;
        }
        if indexed_stmt.freed.is_some() {
            continue;
        }
        let index = &indexed_stmt.index;
        if let FuzzStmt::Load(load) = &indexed_stmt.stmt {
            if load.point_to_freed_resource(program) {
                continue;
            }
            let value_type = load.value.type_name();
            if type_name == value_type {
                // || vec_ty == value_type
                if load.get_ident() == ident {
                    loc_list.push(Location::stmt(index.use_index()));
                }
            }
        }
    }
    rng::choose_iter(loc_list.into_iter())
}

/// Initialize opaque pointer
/// only used in mutation
fn init_opaque_pointer(
    program: &mut FuzzProgram,
    state: &mut ObjectState,
    call_i: usize,
    depth: usize,
) -> eyre::Result<MutateOperation> {
    if depth > config::MAX_DEPTH {
        crate::log!(trace, "reach max depth");
        return Ok(MutateOperation::Nop);
    }

    // if it is an vector, get its first element
    let mut state = state;
    if utils::is_vec_type(state.ty) {
        if let Some(ch) = state.children.first() {
            if utils::is_opaque_pointer(ch.ty) {
                state = &mut state.children[0];
            }
        }
    }

    let ident = state.key.as_str()?;
    let parent_type = state.get_parent().map(|p| p.ty);
    let ps = state.pointer.as_mut().context("pointer has ps")?;
    let type_name = ps.pointer_type;
    crate::log!(trace, "Try to prepare opaque pointer `{}*`", type_name);
    let ptr_type_name = utils::pointer_type(type_name, ps.is_mut);
    let alias_type_name: &str =
        get_alias_type_name(program, call_i, ident, &ptr_type_name, parent_type);

    // try to obtain opaque type from function call
    if let Some(provider) = find_func_with_return_type(&ptr_type_name, alias_type_name) {
        let loc = create_call_stmt_for_ptr(program, ident, provider, depth)?;
        ps.pointer_location = loc;
        crate::log!(trace, "Opaque pointer ready, provider: {provider}");
        let rng_state = rng::save_rng_state();
        return Ok(MutateOperation::PointerRet {
            f_name: provider.to_string(),
            rng_state,
        });
    }

    // try to init a NULL opaque pointer
    crate::log!(trace, "Try to init opaque pointer for `{}*`", type_name);
    let stub_index = program.get_stub_stmt_index().context("no stub")?;
    let rng_state = save_rng_state();
    // Try init function;
    // check and get index of corresponding canonical type name || alias type name
    let candidates = global_gadgets::get_instance()
        .functions
        .iter()
        .filter(|(_, fg)| crate::filter_init_func(fg.f_name))
        .filter_map(|(_, fg)| {
            find_init_arg_pos(fg, &ptr_type_name, alias_type_name).map(|i| (fg, i))
        });

    if let Some((fg, arg_pos)) = rng::choose_iter(candidates) {
        let f_name = fg.f_name;
        crate::log_trace!("choose {f_name} for init opaque pointer");
        if parent_type.is_none() {
            let mut init_call =
                CallStmt::generate_new(program, CallStmt::RELATIVE, f_name, depth + 1)?;
            let mut load_2nd_ptr =
                LoadStmt::generate_constant(fg.arg_types[arg_pos], fg.arg_idents[arg_pos])?;
            let load_2nd_ps = load_2nd_ptr.state.get_pointer_mut()?;
            load_2nd_ps.pointer_location = Location::stmt(stub_index.use_index());
            let load_2nd_ptr_index = program.insert_stmt(stub_index.get() + 1, load_2nd_ptr);
            if !init_call.args.contains(&stub_index) {
                init_call.set_arg(arg_pos, load_2nd_ptr_index.use_index());
            }
            let call_stmt = program.insert_stmt(load_2nd_ptr_index.get() + 1, init_call);
            let _ = program.insert_stmt(
                call_stmt.get() + 1,
                AssertStmt::assert_initialized(stub_index.use_index(), call_stmt),
            );
        } else {
            let load_null =
                LoadStmt::generate_constant(&utils::pointer_type(type_name, true), ident)?;
            let load_null_index = program.insert_or_append_stmt(load_null)?;
            let mut load_2nd_ptr =
                LoadStmt::generate_constant(fg.arg_types[arg_pos], fg.arg_idents[arg_pos])?;
            load_2nd_ptr.state.get_pointer_mut()?.pointer_location =
                Location::stmt(load_null_index.use_index());

            let load_2nd_ptr_index = program.insert_or_append_stmt(load_2nd_ptr)?;
            let mut init_call =
                CallStmt::generate_new(program, CallStmt::RELATIVE, f_name, depth + 1)?;

            // To reference the pointer itself instead of its address,
            // `FieldKey::Pointer` must be specified in the Location Field.
            ps.pointer_location = Location::new(
                load_null_index.use_index(),
                LocFields::new(vec![FieldKey::Pointer]),
            );

            if !init_call.args.contains(&stub_index) {
                init_call.set_arg(arg_pos, load_2nd_ptr_index.use_index());
            }
            let call_stmt = program.insert_or_append_stmt(init_call)?;
            let _ = program.insert_stmt(
                call_stmt.get() + 1,
                AssertStmt::assert_initialized(load_null_index.use_index(), call_stmt),
            );
        }
        crate::log!(
            trace,
            "Init opaque pointer `{}*` with: {:?}",
            type_name,
            f_name
        );
        return Ok(MutateOperation::CallRelatedInsert {
            f_name: f_name.to_owned(),
            arg_pos,
            rng_state,
        });
    }
    // found no possible call can initialize this opaque pointer.
    let rng_state = rng::save_rng_state();
    let loc = create_load_stmt_for_ptr(program, type_name, ident, true, depth)?;
    if loc.is_null() {
        return Ok(MutateOperation::PointerNull);
    }
    ps.pointer_location = loc;
    Ok(MutateOperation::PointerGen { rng_state })
}

/// Find argument position in init function
fn find_init_arg_pos(fg: &FnGadget, type_name: &str, alias_type_name: &str) -> Option<usize> {
    crate::log!(
        trace,
        "find API {} for init arg pos for {type_name} / {alias_type_name}",
        fg.f_name
    );
    fg.arg_types
        .iter()
        .position(|arg_ty| {
            *arg_ty == utils::const_pointer_type(type_name)
                || *arg_ty == utils::mut_pointer_type(type_name)
        })
        .or_else(|| {
            fg.alias_arg_types.iter().position(|alias_ty| {
                *alias_ty == utils::const_pointer_type(alias_type_name)
                    || *alias_ty == utils::mut_pointer_type(alias_type_name)
            })
        })
        .and_then(|i| {
            if let Ok(has_need_init) = crate::inspect_function_constraint_with(fg.f_name, |fc| {
                Ok(fc.arg_constraints[i]
                    .list
                    .iter()
                    .any(|citem| matches! {citem.constraint, Constraint::NeedInit}))
            }) {
                crate::log!(
                    trace,
                    "choose API `{}` for init, has_need_init: {has_need_init}",
                    fg.f_name
                );
                if !has_need_init {
                    return Some(i);
                }
            }
            None
        })
}

/// Get alias type name of ident in arguments
fn get_alias_type_name<'a>(
    program: &FuzzProgram,
    call_i: usize,
    ident: &str,
    ptr_type_name: &'a str,
    parent_ty: Option<&str>,
) -> &'a str {
    let mut alias_type_name: &str = ptr_type_name;
    let mut alias_ident = ident.to_string();
    if let Some(p_ty) = parent_ty {
        alias_ident.push('@');
        alias_ident.push_str(p_ty);
        alias_type_name =
            global_gadgets::get_instance().get_field_alias_type(&alias_ident, ptr_type_name);
    } else if let FuzzStmt::Call(call) = &program.stmts[call_i].stmt {
        for arg_pos in 0..call.fg.arg_idents.len() {
            if call.fg.arg_idents[arg_pos] == ident && call.fg.arg_types[arg_pos] == ptr_type_name {
                alias_type_name = call.fg.alias_arg_types[arg_pos];
            }
        }
    }
    crate::log!(
        trace,
        "find alias with ident: {alias_ident}, type: {ptr_type_name} -> {alias_type_name}"
    );
    alias_type_name
}
