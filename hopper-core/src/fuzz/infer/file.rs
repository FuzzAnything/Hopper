//! Infer file constraint.
//!
//! When an API function reads from or writes to a file, the file name (and FD) provided as an argument must be valid.
//! If the file name is randomly generated, the API call may terminate early, or it could mess up the disk if
//! used as an output stream.
//!
//! When new paths are explored by inputs, we check to see if any file open function (e.g., \verb|fopen|)
//! has been triggered, and compares the file name with the arguments used to invoke the API.
//! If there is a match, a FILE constraint is created for the corresponding argument.
//!
//! We also infer if an integer is a FD.

use std::collections::HashMap;

use eyre::ContextCompat;

use crate::{config, fuzz::*, fuzzer::*, runtime::*, utils, ReviewResult};

impl ReviewResult {
    /// Infer file name by review's memory records
    pub fn infer_file_name(&self, program: &FuzzProgram) -> eyre::Result<bool> {
        let mut found_file = false;
        for rec in &self.mem_records {
            let ty = crate::get_mem_type(rec.ty);
            if ty != crate::MemType::Open {
                continue;
            }
            let Some(stmt_i) = rec.loc.stmt_index.as_ref() else {
                continue;
            };
            crate::log!(trace, "find file record: {:?}", rec);
            for call_i in (0..=rec.call_index).rev() {
                let FuzzStmt::Call(call_stmt) = &program.stmts[call_i].stmt else {
                    continue;
                };
                let Some((arg_pos, mut prefix)) =
                    program.find_stmt_loc_for_call(stmt_i.get(), &call_stmt.args)
                else {
                    continue;
                };
                crate::log_trace!(
                    "find target stmt in call: {call_i}, arg_pos: {arg_pos}, field: {prefix:?}"
                );
                if !rec.loc.fields.is_empty() {
                    prefix.list.extend(rec.loc.fields.list.clone());
                }
                if !prefix.strip_pointer_suffix() && !prefix.list.is_empty() {
                    crate::log!(
                        warn,
                        "file is not a pointer, stmt: {stmt_i}, loc: {}",
                        rec.loc.serialize()?
                    );
                    continue;
                }
                found_file = true;
                let call_name = call_stmt.fg.f_name;
                crate::log!(trace, "prefix: {prefix:?}");
                crate::add_function_constraint(
                    call_name,
                    arg_pos,
                    prefix,
                    crate::Constraint::File {
                        read: rec.mode == 1,
                        is_fd: false,
                    },
                    &format!(
                        "found {call_name}'s arg is file by review in seed {}",
                        program.id
                    ),
                )?;
                break;
            }
        }
        Ok(found_file)
    }
}

impl Fuzzer {
    /// Infer an integer is a FD by mem records merely
    pub fn infer_file_fd(&mut self, program: &FuzzProgram) -> eyre::Result<Option<ConstraintSig>> {
        let fd_list = self.observer.feedback.instrs.get_fd_list();
        let mut used_reserved_fd = HashMap::new();
        for (fd, fd_read) in fd_list {
            if is_valid_fd(fd) {
                continue;
            }
            used_reserved_fd
                .entry(fd)
                .and_modify(|read| *read |= fd_read)
                .or_insert(fd_read);
        }
        if used_reserved_fd.is_empty() {
            return Ok(None);
        }
        let max = program.get_target_index().context("has target index")?;
        for is in &program.stmts {
            let stmt_index = &is.index;
            let FuzzStmt::Load(load) = &is.stmt else {
                continue;
            };
            let Some((_call_i, call_stmt, arg_pos, prefix)) =
                program.find_stmt_loc_in_all_calls(stmt_index.get(), max)
            else {
                continue;
            };
            let num_fields = load
                .state
                .find_fields_with(|s| utils::is_index_or_length_number(s.ty), true);
            for f in num_fields {
                let loc: Location = Location::new(stmt_index.use_index(), f.clone());
                let val = program.find_number_by_loc(loc.clone())? as i32;
                if is_valid_fd(val) {
                    continue;
                }
                if let Some(read) = used_reserved_fd.get(&val) {
                    let fd2 = 9123; // a magic number
                    let op = MutateOperator::new(loc, MutateOperation::IntSet { val: fd2.into() });
                    let _status = self.execute_with_op(program, &op, false)?;
                    let (is_fd, _is_fd_read) = self.observer.contain_fd(fd2);
                    if is_fd {
                        let full_f = prefix.with_suffix(f);
                        return add_function_constraint(
                            call_stmt.fg.f_name,
                            arg_pos,
                            full_f,
                            Constraint::File {
                                read: *read,
                                is_fd: true,
                            },
                            &format!("infer file fd by magic number from seed: {}", program.id),
                        );
                    }
                }
            }
        }
        Ok(None)
    }
}

/// Check if it is a valid fd
pub fn is_valid_fd(fd: i32) -> bool {
    (-1..config::RESERVED_FD_MIN).contains(&fd)
        || (config::RESERVED_FD_MAX..config::RESERVED_FD_HUGE).contains(&fd)
    // (fd >= -1 && fd < RESERVED_FD_MIN) || (fd > RESERVED_FD_MAX && fd < RESERVED_FD_HUGE)
}
