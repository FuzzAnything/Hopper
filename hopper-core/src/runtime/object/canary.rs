//! Adding canary after each vector we created.
//! Canary is protected by page access permission
//!

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Once,
};

use hopper_derive::Serde;

use crate::{config, fuzz::*, runtime::*};

/// Slice warp with canary.
/// The memory blocks are allocated by mmap,
/// and we manage them by ourselfves.
/// Thus, it can't be freed by `free` function.
/// We hook `free`, and filter out pointers starts within
/// the range [MEM_PTR, MEM_PTR + MEM_AREA_SIZE)
pub struct CanarySlice<T> {
    pub ptr: *mut T,
    pub len: usize,
    pub canary: *const u8,
}

pub static MEM_OFFSET: AtomicUsize = AtomicUsize::new(0);
static MEM_INIT: Once = Once::new();

#[inline]
pub fn is_in_canary(addr: *mut u8) -> bool {
    let addr = addr as usize;
    addr >= config::CANARY_PTR as usize
        && addr < config::CANARY_PTR as usize + config::CANARY_AREA_SIZE
}

#[inline]
pub fn get_canary_begin() -> *const u8 {
    config::CANARY_PTR
}

#[derive(Debug, Serde, Clone)]
pub struct CanaryInfo {
    pub stmt_index: usize,
    pub len: usize,
}

/// Simulate the canary allocation, and find pointer address among the canaries.
pub fn find_ptr_in_canary(program: &FuzzProgram, addr: *mut u8) -> Option<CanaryInfo> {
    let page_size = region::page::size() as u64;
    // add page_size since there it an mock canary at beginning
    let mut offset = config::CANARY_PTR as u64 + page_size;
    let addr = addr as u64;
    for is in &program.stmts {
        if let FuzzStmt::Load(load) = &is.stmt {
            if crate::utils::is_vec_type(load.value.type_name()) {
                let len = load.state.children.len();
                if len == 0 {
                    continue;
                }
                let ele_ty = load.state.children[0].ty;
                let ele_size = global_gadgets::get_instance()
                    .get_object_builder(ele_ty)
                    .unwrap()
                    .mem_size() as u64;
                let mem_size = ele_size * len as u64;
                let n = mem_size / page_size;
                let next_canary = offset + (n + 1) * page_size;
                offset = next_canary + page_size;
                // crate::log!(trace, "stmt {} addr: {} - {}", is.index.get(), next_canary, offset);
                if addr >= next_canary && addr < offset {
                    return Some(CanaryInfo {
                        stmt_index: is.index.get(),
                        len,
                    });
                }
            }
        }
    }
    None
}

pub fn clear_canary_protection() {
    let offset = MEM_OFFSET.load(Ordering::SeqCst);
    if offset > 0 {
        unsafe {
            region::protect(
                get_canary_begin() as *mut std::ffi::c_void,
                config::CANARY_AREA_SIZE,
                region::Protection::READ_WRITE_EXECUTE,
            )
            .unwrap();
        }
        protect_first_page();
    }
}

fn protect_first_page() {
    let page_size = region::page::size();
    unsafe {
        region::protect(
            get_canary_begin() as *mut std::ffi::c_void,
            page_size,
            region::Protection::NONE,
        )
        .unwrap();
    }
    MEM_OFFSET.store(page_size, Ordering::SeqCst);
}

impl<T> CanarySlice<T> {
    fn new(len: usize) -> eyre::Result<Self> {
        let page_size = region::page::size();
        MEM_INIT.call_once(|| {
            // we assume the page size is 4KB
            if page_size > 4096 {
                crate::log!(
                    warn,
                    "Page size `{page_size}`is larger than 4096, which may cause error in canary!"
                );
            }
            let mem = region::alloc_at(
                config::CANARY_PTR,
                config::CANARY_AREA_SIZE,
                region::Protection::READ_WRITE_EXECUTE,
            )
            .unwrap();
            crate::log!(
                trace,
                "init memory area for canary: {:?}",
                mem.as_ptr::<u8>()
            );
            if mem.as_ptr::<u8>() != config::CANARY_PTR {
                panic!("fail to allocate memory at MEM_PTR");
            }
            // remain first page as canary
            protect_first_page();
            std::mem::forget(mem);
        });
        let mem_size = std::mem::size_of::<T>() * len;
        let n = mem_size / page_size;
        let r = mem_size % page_size;
        let offset = MEM_OFFSET.load(Ordering::SeqCst);
        let next_ptr = offset + page_size - r;
        let ptr = unsafe { config::CANARY_PTR.add(next_ptr) } as *mut T;
        let next_canary = offset + (n + 1) * page_size;
        if offset >= config::CANARY_AREA_SIZE || next_canary >= config::CANARY_AREA_SIZE {
            eyre::bail!("The pointer exceed the range of cananry! Canary is full!");
        }
        let canary = unsafe { config::CANARY_PTR.add(next_canary) };
        MEM_OFFSET.store(next_canary + page_size, Ordering::SeqCst);

        Ok(Self { ptr, len, canary })
    }

    fn protect(&mut self, flag: region::Protection) -> eyre::Result<()> {
        let page_size = region::page::size();
        unsafe {
            region::protect(self.canary as *mut std::ffi::c_void, page_size, flag)?;
        }
        Ok(())
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    pub fn as_slice(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl<T: ObjFuzzable> ObjValue for CanarySlice<T> {
    fn get_ptr_by_keys(&self, keys: &[FieldKey]) -> eyre::Result<*mut u8> {
        if keys.is_empty() {
            return Ok(self.ptr as *const T as *mut u8);
        }
        if let FieldKey::Index(i) = &keys[0] {
            let list = self.as_slice();
            // try to get a overflow address for inference
            if *i > list.len() {
                return Ok(unsafe { list.as_ptr().add(*i) as *mut u8 });
            }
            return list[*i].get_ptr_by_keys(&keys[1..]);
        }
        eyre::bail!("Key `{:?}` is not fit for CanarySlice", keys);
    }
    fn get_layout(&self, fold_ptr: bool) -> ObjectLayout {
        let list = self.as_slice();
        list.get_layout(fold_ptr)
    }

    fn get_length(&self) -> usize {
        self.len * std::mem::size_of::<T>()
    }
}

impl<T> std::fmt::Debug for CanarySlice<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectLayout")
            .field("ptr", &self.ptr)
            .field("canary", &self.canary)
            .field("len", &self.len)
            .finish()
    }
}

impl<T> Clone for CanarySlice<T> {
    fn clone(&self) -> Self {
        Self::new(self.len).unwrap()
    }
}

impl<T: ObjFuzzable> ObjFuzzable for CanarySlice<T> {}

unsafe impl<T> Sync for CanarySlice<T> {}
unsafe impl<T> Send for CanarySlice<T> {}

impl<T> ObjMutate for CanarySlice<T> {
    fn mutate(&mut self, _state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        unimplemented!();
    }
    fn mutate_by_op(
        &mut self,

        _state: &mut ObjectState,
        _keys: &[FieldKey],
        _op: &MutateOperation,
    ) -> eyre::Result<()> {
        unimplemented!();
    }
}

impl<T: ObjFuzzable> ObjectSerialize for CanarySlice<T> {
    fn serialize_obj(&self, state: &ObjectState) -> eyre::Result<String> {
        if self.len > 0 && state.children.is_empty() {
            let mut buf = String::new();
            buf.push_str("bvec(");
            buf.push_str(&self.len.to_string());
            buf.push_str(")[\"");
            super::seq::serialize_bytes(&mut buf, self.as_slice());
            buf.push_str("\"]");
            return Ok(buf);
        }
        self.as_slice().serialize_obj(state)
    }
}

impl<T: ObjFuzzable> Serialize for CanarySlice<T> {
    fn serialize(&self) -> eyre::Result<String> {
        self.as_slice().serialize()
    }
}

impl<T: ObjFuzzable> ObjectTranslate for CanarySlice<T> {}

impl<T: ObjectDeserialize + ObjGenerate + ObjValue> ObjectDeserialize for CanarySlice<T> {
    fn deserialize_obj(de: &mut Deserializer, state: &mut ObjectState) -> eyre::Result<Self> {
        if de.strip_token("bvec(") {
            let len: usize = de.parse_number()?;
            de.eat_token(")[\"")?;
            let mut canary = CanarySlice::<T>::new(len)?;
            canary.protect(region::Protection::NONE)?;
            let buf = de.next_token_until("\"]")?;
            let list = unsafe { std::slice::from_raw_parts_mut(canary.ptr as *mut u8, len) };
            base64::decode_config_slice(buf, base64::STANDARD, list)?;
            return Ok(canary);
        }
        de.eat_token("vec(")?;
        let len: usize = de.parse_number()?;
        de.eat_token(")[")?;
        let mut canary = CanarySlice::<T>::new(len)?;
        // crate::log!(trace, "protect canary: {:?}", canary);
        canary.protect(region::Protection::NONE)?;
        // crate::log!(trace, "protect done");
        let list = canary.as_mut_slice();
        for v in list {
            let sub_state = state
                .add_child(state.children.len(), std::any::type_name::<T>())
                .last_child_mut()?;
            let element = T::deserialize_obj(de, sub_state)?;
            *v = element;
            de.eat_token(",")?;
        }
        de.eat_token("]")?;
        // crate::log!(trace, "canary done");
        Ok(canary)
    }
}

#[test]
fn test_vec_canary() {
    let mut canary = CanarySlice::new(5).unwrap();
    println!("canary : {canary:?}");
    let canary2 = CanarySlice::<usize>::new(5).unwrap();
    println!("canary2: {canary2:?}");
    {
        let list = canary.as_mut_slice();
        for (i, val) in list.iter_mut().enumerate().take(5) {
            *val = i;
        }
        println!("list: {list:?}");
    }
    {
        let list = canary.as_slice();
        let i = list.len();
        println!("index: {}, val: {}", i, unsafe { list.get_unchecked(i) });
    }
    /*
    {
        canary.protect(region::Protection::NONE).unwrap();
        // crash
        let list = canary.as_slice();
        let i = list.len();
        println!("index: {}, val: {}", i, unsafe { list.get_unchecked(i) } );
    }
    */
    {
        canary
            .protect(region::Protection::READ_WRITE_EXECUTE)
            .unwrap();
        let list = canary.as_slice();
        let i = list.len();
        println!("index: {}, val: {}", i, unsafe { list.get_unchecked(i) });
    }
}
