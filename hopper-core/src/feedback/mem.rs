//! Memory related feedbacks

use super::*;
use crate::runtime::*;

/// Memory-related feedbacks
#[derive(Debug, PartialEq, Eq)]
pub enum MemType {
    Free = 1,
    Malloc,
    Calloc,
    Realloc,
    ReallocMalloc,
    ReallocFree,
    ReallocResize,
    Open = 90,
    Fdopen,
    Lseek,
    Read,
    Write,
    Close,
    Ignore = 100,
}

/// Memeory-related operation
#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct MemOperation {
    /// Address or size
    pub addr: u64,
    /// ID of the instruction
    pub id: u32,
    /// Type
    pub ty: u16,
    /// Invoke at which statement index
    pub stmt_index: u16,
    /// Size
    pub size: u32,
    // suffix of the value in the address.
    pub suffix: [u8; 4],
}

impl ShmIteratorItem for MemOperation {
    fn check(&self) -> bool {
        self.stmt_index < 0xFFFF
    }
    fn get_key(&self) -> u32 {
        self.id
    }
}

impl MemOperation {
    pub fn get_type(&self) -> MemType {
        get_mem_type(self.ty)
    }
}

pub fn get_mem_type(ty: u16) -> MemType {
    match ty {
        1 => MemType::Free,
        2 => MemType::Malloc,
        3 => MemType::Calloc,
        4 => MemType::Realloc,
        5 => MemType::ReallocMalloc,
        6 => MemType::ReallocFree,
        7 => MemType::ReallocResize,
        90 => MemType::Open,
        91 => MemType::Fdopen,
        92 => MemType::Lseek,
        93 => MemType::Read,
        94 => MemType::Write,
        95 => MemType::Close,
        _ => MemType::Ignore,
    }
}

impl std::fmt::Display for MemOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "({}, {:X}, {}, {}, {}, {:?})",
            { self.id },
            { self.addr },
            { self.ty },
            { self.stmt_index },
            { self.size },
            { self.suffix }
        )
    }
}

impl InstrList {
    pub fn set_mem_fn(&mut self) {
        // crate::log!(trace, "free: {:?}", libc::free as *const () );
        self.free_addr = libc::free as *const () as u64;
        self.malloc_addr = libc::malloc as *const () as u64;
        self.calloc_addr = libc::calloc as *const () as u64;
        self.realloc_addr = libc::realloc as *const () as u64;
    }

    /// Count the allocated resources: memory and files
    pub fn count_allocated_resources(&self) -> (usize, usize) {
        let mut num_files = 0;
        let mut mem_bytes = 0;
        for op in self.mem_iter() {
            match op.get_type() {
                MemType::Open => {
                    num_files += 1;
                },
                MemType::Malloc
                | MemType::Calloc
                | MemType::ReallocMalloc
                | MemType::ReallocResize => {
                    mem_bytes += op.size as usize;
                }
                _ => {}
            }
        }
        (num_files, mem_bytes)
    }

    /// Try to associate location with memory-related operation
    pub fn associate_loc_with_mem_op(
        &self,
        index: usize,
        stmts: &[IndexedStmt],
        resource_states: &ResourceStates,
    ) -> Vec<MemRecord> {
        let mut mem_records = vec![];
        for op in self.mem_iter() {
            // crate::log_c!(trace, "mem: {:?}", op);
            let stmt_index = op.stmt_index as usize;
            if stmt_index != index {
                // crate::log_c!(trace, "ignore mem: {:?}", op);
                continue;
            }
            let id = op.id;
            let addr = op.addr as *mut u8;
            let mut size = { op.size } as usize;
            let mut mode = 0;
            let mut is_file = false;
            match op.get_type() {
                MemType::Free | MemType::ReallocFree => {
                    crate::log_c!(trace, "addr {:?} is freed at call {}", addr, stmt_index);
                }
                MemType::Open => {
                    is_file = true;
                    // we reused size for mode
                    mode = size;
                    size = 0;
                    crate::log_c!(trace, "addr {:?} is a file path in {}", addr, stmt_index);
                }
                MemType::Malloc
                | MemType::Calloc
                | MemType::ReallocMalloc
                | MemType::ReallocResize => {
                    // Do not send them to fuzzer's side
                    continue;
                }
                _ => {
                    continue;
                }
            }
            // crate::log!(trace, "try associate mem {:?}", op);
            let mut loc = find_location_at_ptr(stmts, addr, resource_states);
            // try to find the filename in string
            if loc.is_none() && is_file {
                loc = find_string_in_stmts(addr, op.suffix.as_slice(), stmts);
            }
            if let Some(mut loc) = loc {
                // remove index from `find_string`
                if let Some(FieldKey::Index(_)) = loc.fields.list.last() {
                    loc.fields.list.pop();
                }
                let record = MemRecord {
                    id,
                    size,
                    mode,
                    loc,
                    call_index: stmt_index,
                    ty: op.ty,
                };
                mem_records.push(record);
            }
        }
        crate::log_c!(trace, "finish associate mem");
        mem_records
    }

    /// List fd information
    pub fn get_fd_list(&self) -> Vec<(i32, bool)> {
        let mut fd_list = vec![];
        for op in self.mem_iter() {
            match op.get_type() {
             MemType::Fdopen | MemType::Lseek | MemType::Read | MemType::Write | MemType::Close => {
                let fd = op.addr as i32;
                let mode = op.size; 
                let is_read = mode == 1;
                fd_list.push((fd, is_read));
            },
            _ => {}
            }
        }
        fd_list
    }

}
