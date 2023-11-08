//! Current resource state
//! used in harness

use super::*;
use crate::runtime::*;

#[cfg(target_os = "windows")]
use std::collections::{BTreeMap as PtrMap, BTreeSet as PtrSet};
#[cfg(target_family = "unix")]
use std::collections::{BTreeSet as PtrSet, HashMap as PtrMap};

/// States of memory resource
#[derive(Default)]
pub struct ResourceStates {
    /// used for review or not
    review_mode: bool,
    /// list of freed ptrs
    freed_ptrs: PtrSet<*mut u8>,
    /// memory object's size
    ptr_size_map: PtrMap<*mut u8, usize>,
}

impl ResourceStates {
    /// It is used for review
    pub fn set_review(&mut self) {
        self.review_mode = true;
    }

    /// Get size of ptr
    pub fn get_ptr_size(&self, ptr: *mut u8) -> Option<usize> {
        self.ptr_size_map.get(&ptr).copied()
    }

    /// Insert size for specific ptr
    pub fn insert_ptr_size(&mut self, ptr: *mut u8, size: usize) {
        self.ptr_size_map.insert(ptr, size);
    }

    /// Check pointers before filling them
    /// - check if pointer is freed
    #[inline]
    pub fn check_pointer(&self, ptr: *mut u8) -> eyre::Result<()> {
        if !ptr.is_null() {
            eyre::ensure!(
                !self.freed_ptrs.contains(&ptr),
                crate::HopperError::UseAfterFree { ptr }
            );
        }
        Ok(())
    }

    /// Check arguments
    /// - Check if any argument is freed
    pub fn check_arguments(
        &self,
        arg_indices: &[StmtIndex],
        stmts: &[IndexedStmt],
    ) -> eyre::Result<()> {
        for arg_i in arg_indices {
            let is = &stmts[arg_i.get()];
            if let Some(value) = is.stmt.get_value() {
                let layout = value.get_layout(false);
                layout.check_ptr(self, 0)?;
            }
        }
        Ok(())
    }

    /// Update pointers after call functions
    /// - Record which pointers are freed
    pub fn update_pointers_after_call(&mut self) -> eyre::Result<()> {
        let instrs = get_instr_list();
        let stmt_index = instrs.last_stmt_index() as u16;
        for op in instrs.mem_iter() {
            if op.stmt_index == stmt_index {
                crate::log!(trace, "mem op: {} ", op);
                let ty = op.get_type();
                // find out freed pointer
                match ty {
                    MemType::Free | MemType::ReallocFree => {
                        if op.addr == 0 {
                            continue;
                        }
                        let ptr = op.addr as *mut u8;
                        if !self.freed_ptrs.insert(ptr) && canary::is_in_canary(ptr) {
                            // double free
                            eyre::bail!(crate::HopperError::DoubleFree { ptr });
                        }
                        self.ptr_size_map.insert(ptr, 0);
                    }
                    _ => {}
                }

                match ty {
                    MemType::Malloc
                    | MemType::Calloc
                    | MemType::ReallocMalloc
                    | MemType::ReallocResize => {
                        let size = op.size as usize;
                        if size > 0 {
                            let ptr = op.addr as *mut u8;
                            // store memory size (only for review mode)
                            // if self.review_mode {
                            self.ptr_size_map.insert(ptr, size);
                            if self.freed_ptrs.contains(&ptr) {
                                self.freed_ptrs.remove(&ptr);
                            }
                        } else {
                            crate::log!(debug, "zero size memory record!");
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

#[test]
fn test_check_resource() {
    let mut resource_states = ResourceStates::default();
    let ptr = 123 as *mut u8;
    resource_states.freed_ptrs.insert(ptr);
    assert!(resource_states.check_pointer(ptr).is_err());
}
