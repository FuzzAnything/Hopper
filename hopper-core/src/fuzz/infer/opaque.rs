//! Infer the type is opaque type or not

use eyre::ContextCompat;

use crate::{fuzz::*, fuzzer::*, log, runtime::*, utils, CrashSig};

impl Fuzzer {
    /// If we update a call's return fails, we assume the return's type is opaque that can not be mutated.
    pub fn infer_opaque_if_update_fail(
        &mut self,
        program: &FuzzProgram,
    ) -> eyre::Result<Option<ConstraintSig>> {
        let Some(op) = program.ops.first() else {
            return Ok(None);
        };
        if matches!(op.op, MutateOperation::CallUpdate { fields: _, ops: _ }) {
            let call_i = op.key.get_index()?.get();
            crate::log!(trace, "find update operation for {call_i}");
            if let Some(call) = program.get_call_stmt(call_i) {
                let f_name = call.fg.f_name;
                if crate::inspect_function_constraint_with(f_name, |fc| {
                    Ok(fc.ret.is_partial_opaque)
                })? {
                    crate::log!(trace, "function {f_name} has partial opaque return");
                    if let Some(alias_ret_ty) = call.fg.alias_ret_type {
                        let ret_ty: &str = call.fg.ret_type.unwrap();
                        if let Some(c) = self.set_opaque_type(ret_ty, alias_ret_ty)? {
                            return Ok(Some(c));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    pub fn infer_opaque_type(
        &mut self,
        program: &FuzzProgram,
        fail_at: usize,
        crash_sig: &CrashSig,
    ) -> eyre::Result<Option<ConstraintSig>> {
        let Some(canary_info) = crash_sig.get_canary_info() else {
            return Ok(None);
        };
        // skip primitive types/pointers
        if let FuzzStmt::Load(load) = &program.stmts[canary_info.stmt_index].stmt {
            if let Some(inner_ty) = utils::get_vec_inner(load.state.ty) {
                if utils::is_primitive_type(inner_ty) {
                    return Ok(None);
                }
            }
        }

        if let Some((call_i, call_stmt, arg_pos, fields)) =
            program.find_stmt_loc_in_all_calls(canary_info.stmt_index, fail_at)
        {
            let mut ptr_fields = fields;
            let last_one = ptr_fields.list.pop();
            if Some(FieldKey::Pointer) != last_one {
                return Ok(None);
            }
            crate::log!(
                trace,
                "try to infer if it is a opaque type, index: {}",
                canary_info.stmt_index
            );
            let loc = ptr_fields
                .to_loc_for_refining(program, &call_stmt.args[arg_pos], &LocFields::default())
                .context("can't find loc for infer opaque type")?;
            let op = MutateOperator::new(loc, MutateOperation::InitOpaqueForInfer { call_i });
            // verify
            for _ in 0..16 {
                let mut p = program.clone();
                p.mutate_program_by_op(&op)?;
                crate::log!(trace, "mutate ops: {:?}", p.ops);
                p.refine_program()?;
                let Some(op) = p.ops.first() else {
                    continue;
                };
                let mut is_opaque_return = false;
                let (ptr_ty, ptr_alias_ty) = match &op.op {
                    MutateOperation::PointerRet {
                        f_name,
                        rng_state: _,
                    } => {
                        crate::inspect_function_constraint_with(f_name, |fc| {
                            if fc.ret.is_partial_opaque {
                                crate::log!(trace, "{f_name} is partial opaque return");
                                is_opaque_return = true;
                            }
                            Ok(())
                        })?;
                        let fg = global_gadgets::get_instance().get_func_gadget(f_name)?;

                        (fg.ret_type.unwrap(), fg.alias_ret_type.unwrap())
                    }
                    MutateOperation::CallRelatedInsert {
                        f_name,
                        arg_pos,
                        rng_state: _,
                    } => {
                        let fg = global_gadgets::get_instance().get_func_gadget(f_name)?;
                        (fg.arg_types[*arg_pos], fg.alias_arg_types[*arg_pos])
                    }
                    _ => return Ok(None),
                };
                // skip primitive pointer
                if let Some(inner_ty) = utils::get_pointer_inner(ptr_ty) {
                    if utils::is_primitive_type(inner_ty) {
                        return Ok(None);
                    }
                }
                crate::log!(trace, "program: {}", p.serialize()?);
                let status = self.executor.execute_program(&p)?;
                let last_stmt = self.observer.feedback.last_stmt_index();
                crate::log!(trace, "last_stmt: {last_stmt}");
                // if !crash_sig.is_overflow_at_same_rip() {
                if status.is_normal() && (is_opaque_return || last_stmt >= p.stmts.len()) {
                    let ret = self.set_opaque_type(ptr_ty, ptr_alias_ty)?;
                    return Ok(ret);
                }
            }
        }
        Ok(None)
    }

    /// Set `ptr_ty` as opaque type
    pub fn set_opaque_type(
        &mut self,
        ptr_ty: &str,
        ptr_alias_ty: &str,
    ) -> eyre::Result<Option<ConstraintSig>> {
        let opaque_ty = if let Some(inner_ty) = utils::get_pointer_inner(ptr_ty) {
            if utils::is_primitive_type(inner_ty) {
                if let Some(alias_inner) = utils::get_pointer_inner(ptr_alias_ty) {
                    if utils::is_primitive_type(alias_inner) {
                        return Ok(None);
                    }
                    alias_inner
                } else {
                    ptr_alias_ty
                }
            } else {
                inner_ty
            }
        } else {
            return Ok(None);
        };
        crate::log!(trace, "opaque_ty is : {opaque_ty}");
        if utils::is_opaque_type(opaque_ty) {
            crate::log!(trace, "skip, {opaque_ty} is opaque!");
            return Ok(None);
        }
        log!(info, "set type {opaque_ty} as opaque");
        crate::log_new_constraint(&format!("set type {opaque_ty} as opaque"));
        global_gadgets::get_mut_instance().add_opaque_type(opaque_ty);
        self.executor
            .set_config(crate::OPAQUE_CONFIG_KEY, opaque_ty)?;
        let sig = ConstraintSig {
            f_name: opaque_ty.to_string(),
            arg_pos: 0,
            fields: LocFields::default(),
            constraint: Constraint::OpaqueType,
        };
        Ok(Some(sig))
    }
}
