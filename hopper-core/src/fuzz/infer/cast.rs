//! Infer cast constraint.
//!
//! Due to missing layout information of the void type, developers have to generate objects with
//! concrete types and cast their references to the void pointers.
//!
//! We assume that their pointees do not contain any pointer.
//! Therefore, they can be cast from a large enough random byte array, and we add CAST constraints
//! that treat them as char* type.
//!
//! For other illegal access, if there are CAST constraints for the arguments, we tries to mutate
//! the byte array pointed to by the arguments. If the illegal address varies with the mutated bytes,
//! the void pointer may be interpreted as a structure containing pointers.
//! Thus, We remove the CAST constraints with char* type.

use crate::{fuzz::*, fuzzer::*, runtime::*, CrashSig};

impl Fuzzer {
    /// Infer if the void type is casted to a concrete type that contain pointers.
    /// If so, we can't use a huge byte array to interpret the void object.
    pub fn infer_void_cast(
        &mut self,
        program: &FuzzProgram,
        fail_at: usize,
        crash_sig: &CrashSig,
    ) -> eyre::Result<bool> {
        let Some(call) = program.get_call_stmt(fail_at) else {
            return Ok(false);
        };
        let f_name = call.fg.f_name;

        // find all existing casts
        let mut casts = vec![];
        let prefix = LocFields::default();
        inspect_function_constraint_with(f_name, |fc| {
            for (arg_pos, tc) in fc.arg_constraints.iter().enumerate() {
                if tc.list.is_empty() {
                    continue;
                }
                for c in tc.list.iter() {
                    if c.constraint.is_void_cast() {
                        casts.push((arg_pos, c.key.clone()));
                    }
                }
            }
            Ok(())
        })?;

        for (arg_pos, fields) in casts {
            crate::log_trace!("try to remove void cast: `{f_name}`, {arg_pos}, {fields:?}");
            let stmt_index = &call.args[arg_pos];
            let mut ptr_fields = fields.clone();
            ptr_fields.push(FieldKey::Pointer);
            let loc = ptr_fields.to_loc_for_refining(program, stmt_index, &prefix);
            if loc.is_none() {
                crate::log!(trace, "can't find loc: {loc:?}");
                continue;
            }
            let loc = loc.unwrap();
            let FuzzStmt::Load(load) = &program.stmts[loc.get_index()?.get()].stmt else {
                continue;
            };
            let len = load.value.get_length();
            crate::log!(trace, "load : {}, length: {len}", load.value.serialize()?);

            for i in 0..len {
                // if the pointer address > maximal address in x86, si_addr becomes 0.
                // so we set word to zero instead of single byte.
                let mut key = Location::null();
                key.fields.push(FieldKey::Index(i));
                let set_word_zero = MutateOperation::BufHavoc {
                    use_bytes: 2,
                    swap: false,
                    op: Box::new(MutateOperator::new(
                        key,
                        MutateOperation::IntSet { val: 0.into() },
                    )),
                };
                let op = MutateOperator::new(loc.clone(), set_word_zero);
                let _status = self.execute_with_op(program, &op, false)?;
                let cur_crash_sig = crate::get_crash_sig(None);
                if cur_crash_sig.is_none() {
                    continue;
                }
                let cur_crash_sig = cur_crash_sig.unwrap();
                crate::log!(trace, "sig: {crash_sig:?} vs {cur_crash_sig:?}");
                if cur_crash_sig.rip == crash_sig.rip && cur_crash_sig.addr != crash_sig.addr {
                    // address changes, remove void constriant
                    log_new_constraint(&format!(
                        "remove void constraint for `{f_name}`, {arg_pos}, {fields:?}"
                    ));
                    inspect_function_constraint_mut_with(f_name, |fc| {
                        let tc = &mut fc.arg_constraints[arg_pos];
                        tc.list
                            .retain(|c| !(c.key == fields && c.constraint.is_void_cast()));
                        Ok(())
                    })?;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
