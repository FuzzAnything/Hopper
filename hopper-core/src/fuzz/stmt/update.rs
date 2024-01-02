//! Update other statment's field by another
//! e.g update call statement 's return by a load statement

use eyre::ContextCompat;

use crate::utils;

use super::*;

impl WeightedItem for UpdateStmt {}

impl StmtMutate for UpdateStmt {}

/// Append update statement after call statement
/// update should used incompatiblely
pub fn append_update_stmt(
    program: &mut FuzzProgram,
    call: &mut CallStmt,
) -> eyre::Result<MutateOperator> {
    if call.ret_ir.is_empty() || call.is_leaf() {
        return Ok(MutateOperator::nop());
    }
    let call_index = program.get_stub_stmt_index().context("no stub")?;
    // no one use it as argument
    if call_index.get_ref_used() <= 2 {
        return Ok(MutateOperator::nop());
    }
    // we want to skip the opaque type, especially those that are manually marked opaque type.
    // However, ret_ir might not have a full structual layout, therefore
    // we might still update a particular field of an partially exported opaque type
    let mut unused = vec![];
    let mut opeaque_prefix = vec![];
    for (i, ir) in call.ret_ir.iter().enumerate() {
        let ty_name = ir.value.type_name();
        let key = ir.fields.as_slice();
        if key.len() > 5 || utils::is_opaque_type(ty_name) || utils::is_opaque_vec(ty_name) {
            opeaque_prefix.push(key);
            continue;
        }
        // skip those pointers inside opaque value
        if opeaque_prefix.iter().any(|p| key.starts_with(p)) {
            continue;
        }
        // skip private fields and empty list
        if ir.state.is_private_field() || ir.value.get_length() == 0 {
            continue;
        }
        // skip long vector for custom structure 
        if ir.value.get_length() > 1 && !utils::is_primitive_type(ty_name) {
            continue;
        }
        if ir.used.is_none() {
            crate::log!(trace, "key {key:?} is added for updated");
            unused.push(i);
        }
    }
    // choose any unused
    if let Some(ir_i) = rng::choose_iter(unused.into_iter()) {
        let ir = &call.ret_ir[ir_i];
        // copy as load statement
        let mut state = ir.state.clone_with_program(program);
        // make call's ident to return
        if ir.fields.as_slice() == [FieldKey::Pointer] {
            state.set_ident(&call.ident);
        }
        let mut load = LoadStmt::new(
            ir.value.clone(),
            // this load stmt shares state with call_ret_ir
            state,
        );
        // then mutate load statement
        let load_mutate_op = load.mutate(program)?;
        let insert_i = call.ret_ir[ir_i + 1..]
            .iter()
            .find_map(|ir| ir.used.as_ref().map(|i| i.get()))
            .unwrap_or_else(|| call_index.get() + 1);
        let load_i = program.insert_stmt(insert_i + 1, load);
        // add update statement
        let dst = WeakLocation {
            stmt_index: Some(call_index.downgrade()),
            fields: call.ret_ir[ir_i].fields.clone(),
        };
        let update = UpdateStmt::new(load_i, dst);
        let update_i = program.insert_stmt(insert_i + 2, update);
        call.ret_ir[ir_i].used = Some(update_i.downgrade());
        let ir = &call.ret_ir[ir_i];
        crate::log!(
            trace,
            "insert update : set call {}'s {} fields to {}",
            call_index.get(),
            ir.fields.serialize()?,
            load_mutate_op.serialize()?
        );
        return Ok(MutateOperator::stmt_op(MutateOperation::CallUpdate {
            fields: ir.fields.clone(),
            ops: vec![load_mutate_op],
        }));
    }

    Ok(MutateOperator::stmt_op(MutateOperation::Nop))
}

#[test]
fn test_update_mutate() {
    use crate::{feedback, test};
    let mut program = FuzzProgram::default();
    let call_1 = program.append_stmt(FuzzStmt::Stub);
    let mut call_last = test::generate_call_stmt("test_do_nothing1");
    call_last.ident = CallStmt::TARGET.to_string();
    call_last.contexts.push(call_1);
    let _c = program.append_stmt(call_last);
    // stub
    let mut call = test::generate_call_stmt("create_test_ptr");
    let resource_states = feedback::ResourceStates::default();
    let val = Box::new(test::create_test_ptr()) as FuzzObject;
    let ret = feedback::convert_ret_to_ir(&val, &resource_states);
    println!("ret: {ret:?}");
    call.ret_ir = ret.ir;
    if let Some(first) = call.ret_ir.first_mut() {
        if first.fields.is_empty() {
            first.used = Some(program.stmts[0].index.downgrade());
        }
    }
    // println!("ir: {:?}", call.ret_ir);
    append_update_stmt(&mut program, &mut call).unwrap();
    append_update_stmt(&mut program, &mut call).unwrap();
    append_update_stmt(&mut program, &mut call).unwrap();
    let op = append_update_stmt(&mut program, &mut call).unwrap();
    assert!(op.is_nop());
    let _ = program.withdraw_stmt(call.into());
    println!("program: {}", program.serialize().unwrap());
    // the update fields should be from nested to shallow
    let mut last_update_f_len = 1000;
    for is in &program.stmts {
        if let FuzzStmt::Update(update) = &is.stmt {
            let f_len = update.dst.fields.len();
            assert!(f_len < last_update_f_len);
            last_update_f_len = f_len;
        }
    }

    // test remove ret
    println!("check remove ret");
    if let FuzzStmt::Call(call) = &mut program.stmts[0].stmt {
        let last = call.ret_ir.pop().unwrap();
        println!("remove {}", last.fields.serialize().unwrap());
        program.check_update().unwrap();
        println!("program: {}", program.serialize().unwrap());
        for is in &program.stmts {
            if let FuzzStmt::Update(update) = &is.stmt {
                assert_ne!(update.dst.fields, last.fields);
            }
        }
    }
}
