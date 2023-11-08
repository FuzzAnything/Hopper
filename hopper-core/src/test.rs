//! Types and functions for testing hopper, which can be used as gadgets.
//! - Types : add `Fuzz` derive
//! - Functions: add `fuzz` attribute

use crate::{runtime::*, ObjGenerate};
use hopper_derive::{fuzz, Fuzz};

pub fn generate_load_stmt<T: ObjFuzzable + ObjGenerate>(ident: &str, ty: &str) -> LoadStmt {
    let mut state = LoadStmt::new_state(ident, ty);
    let value = Box::new(T::generate_new( &mut state).unwrap());
    LoadStmt::new(value, state)
}

pub fn generate_call_stmt(f_name: &str) -> CallStmt {
    let fg = global_gadgets::get_instance()
        .get_func_gadget(f_name)
        .unwrap()
        .clone();
    CallStmt::new("test_call".to_string(), f_name.to_string(), fg)
}

pub type TestBool = u8;

#[derive(Debug, Clone, Fuzz)]
pub struct TestType {
    name: [char; 10],
    flag: bool,
    price: f32,
    p: FuzzMutPointer<u8>,
    index: i32,
}

#[derive(Debug, Clone, Fuzz)]
pub struct ArrayWrap {
    p: FuzzMutPointer<u8>,
    len: u32,
}

#[derive(Debug, Clone, Fuzz)]
pub struct ListNode {
    val: i32,
    next: FuzzMutPointer<ListNode>,
}

#[fuzz]
pub fn create_list_node() -> FuzzMutPointer<ListNode> {
    let ret = Box::new(ListNode {
        val: 1,
        next: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode>")),
    });
    FuzzMutPointer::<ListNode>::new(Box::into_raw(ret))
}

#[derive(Debug, Clone, Fuzz)]
pub struct ListNode2 {
    val: i32,
    f1: FuzzMutPointer<ListNode2>,
    f2: FuzzMutPointer<ListNode2>,
    f3: FuzzMutPointer<ListNode2>,
}

#[fuzz]
pub fn list_node() -> ListNode {
    ListNode {
        val: 1,
        next: FuzzMutPointer::null(&mut ObjectState::root("", "FuzzMutPointer<ListNode>")),
    }
}

#[fuzz]
pub fn list_node2() -> ListNode2 {
    ListNode2 {
        val: 1,
        f1: FuzzMutPointer::null(&mut ObjectState::root("", "FuzzMutPointer<ListNode>")),
        f2: FuzzMutPointer::null(&mut ObjectState::root("", "FuzzMutPointer<ListNode>")),
        f3: FuzzMutPointer::null(&mut ObjectState::root("", "FuzzMutPointer<ListNode>")),
    }
}

#[fuzz]
pub fn visi_list_node(_first: ListNode) {}

#[fuzz]
pub fn visit_reference_circle(_first: FuzzMutPointer<ListNode>) {}

#[fuzz]
pub fn create_u8_ptr() -> FuzzMutPointer<u8> {
    let mut arr = vec![0_u8; 8];
    let ptr = arr.as_mut_ptr();
    println!("u8 ptr: {ptr:?}");
    std::mem::forget(arr);
    FuzzMutPointer::<u8>::new(ptr)
}

#[fuzz]
pub fn create_test_ptr() -> FuzzMutPointer<TestType> {
    let test = Box::new(TestType {
        name: ['a'; 10],
        flag: false,
        price: 0.2,
        p: create_u8_ptr(),
        index: 0,
    });
    // std::mem::forget(test);
    FuzzMutPointer::<TestType>::new(Box::into_raw(test))
}

#[fuzz]
pub fn func_add(a: u8, b: u8) -> u8 {
    a.saturating_add(b)
}

#[fuzz]
fn func_create(_p: FuzzConstPointer<u8>) -> [u8; 10] {
    [0; 10]
}

#[fuzz]
pub fn func_use(_m: [u8; 10]) {}

#[fuzz]
pub fn func_struct(test: TestType) -> bool {
    test.flag && test.index == 123
}

#[fuzz]
fn test_arr(ptr: FuzzMutPointer<u8>, len: u32) -> bool {
    if ptr.get_inner().is_null() {
        return false;
    }
    for i in 0..len {
        println!("ptr-{}: {:?}", i, unsafe {
            ptr.get_inner().add(i as usize)
        })
    }
    true
}

#[fuzz]
fn test_mutate_arr(ptr: FuzzMutPointer<FuzzMutPointer<u8>>, len: FuzzMutPointer<u32>) -> bool {
    println!("ptr: {ptr:?}, len: {len:?}");
    true
}

#[fuzz]
fn test_use_array_wrap(_warp: ArrayWrap) {}

#[fuzz]
fn test_index(test: TestType) -> bool {
    if test.p.get_inner().is_null() {
        return false;
    }
    println!("ptr-{}: {:?}", test.index, unsafe {
        test.p.get_inner().add(test.index as usize)
    });
    true
}

#[fuzz]
pub fn test_do_nothing1() {}

#[fuzz]
pub fn test_do_nothing2() {}

#[fuzz]
fn test_fn_pointer(fn_ptr: Option<fn()>) {
    println!("fn_ptr: {fn_ptr:?}");
}

#[fuzz]
fn test_bool(_b: TestBool) {}

#[fuzz]
pub fn reference_circle_1() -> FuzzMutPointer<ListNode> {
    let first = Box::new(ListNode {
        val: 1,
        next: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode>")),
    });
    let first_raw = Box::into_raw(first);
    let first_ptr = FuzzMutPointer::<ListNode>::new(first_raw);
    let second = Box::new(ListNode {
        val: 1,
        next: first_ptr,
    });
    unsafe {
        (*first_ptr.get_inner()).next = FuzzMutPointer::<ListNode>::new(Box::into_raw(second));
    }
    first_ptr
}

#[fuzz]
pub fn reference_circle_2() -> FuzzMutPointer<ListNode2> {
    let first = Box::new(ListNode2 {
        val: 1,
        f1: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode2>")),
        f2: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode2>")),
        f3: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode2>")),
    });
    let first_raw = Box::into_raw(first);
    println!("first_raw: {:p}", &first_raw);
    let first_ptr = FuzzMutPointer::<ListNode2>::new(first_raw);
    let second = Box::new(ListNode2 {
        val: 2,
        f1: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode2>")),
        f2: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode2>")),
        f3: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode2>")),
    });
    let second_raw = Box::into_raw(second);
    println!("second_raw: {:p}", &second_raw);
    unsafe {
        (*first_ptr.get_inner()).f1 = FuzzMutPointer::<ListNode2>::new(second_raw);
        (*first_ptr.get_inner()).f2 = FuzzMutPointer::<ListNode2>::new(second_raw);
    }
    first_ptr
}

#[fuzz]
pub fn reference_circle_3() -> FuzzMutPointer<ListNode2> {
    let first = Box::new(ListNode2 {
        val: 1,
        f1: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode2>")),
        f2: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode2>")),
        f3: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode2>")),
    });
    let first_raw = Box::into_raw(first);
    println!("first_raw: {:p}", &first_raw);
    let first_ptr = FuzzMutPointer::<ListNode2>::new(first_raw);
    let second = Box::new(ListNode2 {
        val: 2,
        f1: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode2>")),
        f2: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode2>")),
        f3: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode2>")),
    });
    let second_raw = Box::into_raw(second);
    println!("second_raw: {:p}", &second_raw);
    let second_ptr = FuzzMutPointer::<ListNode2>::new(second_raw);
    unsafe {
        (*first_ptr.get_inner()).f1 = FuzzMutPointer::<ListNode2>::new(second_raw);
        (*second_ptr.get_inner()).f2 = FuzzMutPointer::<ListNode2>::new(first_raw);
    }
    first_ptr
}

#[fuzz]
pub fn reference_circle_4() -> FuzzMutPointer<ListNode> {
    let first = Box::new(ListNode {
        val: 1,
        next: FuzzMutPointer::null(&mut ObjectState::root("prev", "FuzzMutPointer<ListNode>")),
    });
    let first_raw = Box::into_raw(first);
    let first_ptr = FuzzMutPointer::<ListNode>::new(first_raw);
    unsafe {
        (*first_ptr.get_inner()).next = first_ptr;
    }
    first_ptr
}

#[fuzz]
pub fn test_one(k: usize) -> usize {
    k
}

#[fuzz]
pub fn test_non_zero(k: usize) -> usize {
    k
}