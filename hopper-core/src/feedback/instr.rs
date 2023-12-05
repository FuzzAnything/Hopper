use std::collections::HashMap;

use crate::{config, runtime::*};

use super::*;

const CMP_ENTRY_SIZE: usize = std::mem::size_of::<CmpOperation>();
const CMP_LIST_LEN: usize = config::CMP_LIST_AREA / CMP_ENTRY_SIZE;
const MEM_ENTRY_SIZE: usize = std::mem::size_of::<MemOperation>();
const MEM_LIST_LEN: usize = config::MEM_LIST_AREA / MEM_ENTRY_SIZE;

#[repr(packed)]
pub struct InstrList {
    // cmp instructions
    pub cmps: [CmpOperation; CMP_LIST_LEN],
    // memory related functions
    pub mems: [MemOperation; MEM_LIST_LEN],
    // offset of cmp
    pub cmp_offset: u32,
    // offset of mem
    pub mem_offset: u32,
    // current index of stmt
    pub stmt_index: u32,
    pub loop_cnt: u32,
    // function pointer address of libc's memory related functions
    pub free_addr: u64,
    pub malloc_addr: u64,
    pub calloc_addr: u64,
    pub realloc_addr: u64,
    pub rip_addr: u64,
    pub segv_addr: u64,
}

// Cmplist can be a shared memory
impl SHMable for InstrList {
    fn name() -> &'static str {
        "instr"
    }
    fn shmid_env_var() -> &'static str {
        config::INSTR_SHMID_VAR
    }
    fn ptr_base() -> *const libc::c_void {
        config::SHM_INSTR_BASE as *const libc::c_void
    }
    fn buf_size() -> usize {
        config::CMP_LIST_AREA + config::MEM_LIST_AREA + 64
    }
    #[cfg(feature = "llvm_mode")]
    fn post_hander(ptr: *const u8) {
        let ptr = ptr as *const InstrList;
        unsafe { 
            __hopper_stmt_index_ptr = std::ptr::addr_of!((*ptr).stmt_index);
        };
    }
}

#[no_mangle]
pub static mut __hopper_stmt_index_ptr: *const u32 = std::ptr::null();

impl InstrList {
    /// Get last stmt index
    #[inline]
    pub fn last_stmt_index(&self) -> usize {
        if cfg!(feature = "e9_mode") {
            self.stmt_index as usize
        } else {
            globl::current_stmt_index() as usize
        }
    }

    /// Length of CmpOp
    #[inline]
    pub fn cmp_len(&self) -> usize {
        self.cmp_offset as usize
    }

    /// Iterator for cmps
    #[inline]
    pub fn cmp_iter(&self, max_counter: Option<usize>) -> ShmBufIter<'_, CmpOperation> {
        ShmBufIter {
            list: &self.cmps,
            len: self.cmp_len(),
            offset: 0,
            counter: max_counter.map(ItemCounter::new),
        }
    }

    /// Length of CmpOp
    #[inline]
    pub fn mem_len(&self) -> usize {
        self.mem_offset as usize
    }

    /// Iterator for frees
    #[inline]
    pub fn mem_iter(&self) -> ShmBufIter<'_, MemOperation> {
        ShmBufIter {
            list: &self.mems,
            len: self.mem_len(),
            offset: 0,
            counter: None,
        }
    }

    /// Add a cmp into list
    pub fn add_cmp(&mut self, id: u32, ty: u16, operand1: u64, operand2: u64, size: u32) {
        self.add_cmp_with_prefix(id, ty, operand1, operand2, size, 0); 
    }

    pub fn add_cmp_with_prefix(&mut self, id: u32, ty: u16, operand1: u64, operand2: u64, size: u32, prefix: u32) {
        let mut offset = self.cmp_offset as usize;
        if offset >= CMP_LIST_LEN {
            offset = 0;
        }
        let stmt_index = self.last_stmt_index() as u16;
        self.cmps[offset] = CmpOperation {operand1, operand2, id, size, ty, stmt_index, state: prefix};
        self.cmp_offset =  offset as u32 + 1; 
    }

    /// Add a mem into list with suffix
    pub fn add_mem_with_suffix(&mut self, id: u32, ty: u16, addr: u64, size: u32, suffix: [u8; 4]) {
        let mut offset = self.mem_offset as usize;
        if offset >= MEM_LIST_LEN {
            offset = 0;
        }
        let stmt_index = self.last_stmt_index() as u16;
        self.mems[offset] = MemOperation {addr, id, ty, stmt_index, size, suffix};
        self.mem_offset = offset as u32 + 1;
    }

    /// Add a mem into list
    pub fn add_mem(&mut self, id: u32, ty: u16, addr: u64, size: u32) {
        self.add_mem_with_suffix(id, ty, addr, size, [0; 4]);
    }

    pub fn inner_clear(&mut self) {
        unsafe {
            libc::memset(
                self.cmps.as_ptr() as *mut libc::c_void,
                0,
                config::CMP_LIST_AREA,
            )
        };
        // all entry will overwrite
        /*
        unsafe {
            libc::memset(
                self.mems.as_ptr() as *mut libc::c_void,
                0,
                self.mem_offset as usize * MEM_ENTRY_SIZE,
            )
        };
        */
        self.cmp_offset = 0;
        self.mem_offset = 0;
        self.stmt_index = 0;
        self.free_addr = 0;
        self.malloc_addr = 0;
        self.calloc_addr = 0;
        self.realloc_addr = 0;
        self.rip_addr = crate::config::DEFAULT_RIP_ADDR;
        self.segv_addr = crate::config::DEFAULT_SEGV_ADDR;
    }
}

/// Iterator for list in shared memoery
pub struct ShmBufIter<'a, T: ShmIteratorItem> {
    pub list: &'a [T],
    pub len: usize,
    pub offset: usize,
    pub counter: Option<ItemCounter>,
}

pub struct ItemCounter {
    pub map: HashMap<u32, usize>,
    pub max: usize,
}

/// Check if the item is valid or not, otherwise break the iter.
pub trait ShmIteratorItem {
    fn check(&self) -> bool;
    fn get_key(&self) -> u32;
}

impl<'a, T: ShmIteratorItem> Iterator for ShmBufIter<'a, T> {
    type Item = &'a T;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.len {
            return None;
        }
        let ele = &self.list[self.offset];
        if !ele.check() {
            return None;
        }
        self.offset += 1;
        if let Some(counter) = self.counter.as_mut() {
            if counter.exceed(ele.get_key()) {
                return self.next();
            }
        }
        Some(ele)
    }
}

impl ItemCounter {
    pub fn new(max: usize) -> Self {
        Self {
            map: HashMap::new(),
            max,
        }
    }
    pub fn exceed(&mut self, key: u32) -> bool {
        let cnt = self.map.entry(key).and_modify(|counter| *counter += 1).or_insert(1);
        *cnt >= self.max
    }
}

/// Find location at specific ptr
pub fn find_location_at_ptr(
    stmts: &[IndexedStmt],
    ptr: *mut u8,
    resource_states: &ResourceStates,
) -> Option<Location> {
    if ptr.is_null() {
        return None;
    }
    let is_in_canary = is_in_canary(ptr);
    for indexed_stmt in stmts.iter().rev() {
        let index = &indexed_stmt.index;
        match &indexed_stmt.stmt {
            FuzzStmt::Load(load) => {
                if is_in_canary {
                    let mut layout = load.value.get_layout(true);
                    // do not load pointer's layout
                    layout.lazy_loader = None;
                    if let Some(fields) = layout.find_ptr(ptr, resource_states) {
                        return Some(Location::new(index.use_index(), fields));
                    }
                }
            }
            FuzzStmt::Call(call) => {
                if let Some(ret) = &call.ret {
                    let layout = ret.get_layout(false);
                    // crate::log!(trace, "layout: {:?}", layout);
                    if let Some(fields) = layout.find_ptr(ptr, resource_states) {
                        return Some(Location::new(index.use_index(), fields));
                    }
                }
            }
            FuzzStmt::File(file) => {
                if let Some(f) = file.get_value() {
                    if let Some(f_ptr) = f.downcast_ref::<FuzzMutPointer::<i8>>() {
                        if f_ptr.get_inner() as *mut u8 == ptr {
                            return Some(Location::new(index.use_index(), LocFields::default()));
                        }
                    } else if let Some(f_ptr) = f.downcast_ref::<FuzzConstPointer::<i8>>() {
                        if f_ptr.get_inner() as *mut u8 == ptr {
                            return Some(Location::new(index.use_index(), LocFields::default()));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}
