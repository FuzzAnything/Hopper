//! Runtime module
//! includes IR of functions, calls, variables .. of programs,
//! how they wil be executed(eval),
//! their trais for serde, fuzz(new, mutating)..,
//! and stored them as gadgets
mod func;
#[macro_use]
mod object;
mod stmt;

mod gadgets;
mod loc;
mod program;
mod serde;
mod translate;

use std::marker::PhantomData;

pub use func::*;
pub use gadgets::*;
pub use loc::*;
pub use object::*;
pub use program::*;
pub use serde::*;
pub use stmt::*;
pub use translate::*;
/// Custom void type
#[repr(transparent)]
#[derive(Debug, Default)]
pub struct FuzzVoid(u8); // just hold something useless

/// Mutatable pointer: *mut
#[repr(transparent)]
#[derive(Debug)]
pub struct FuzzMutPointer<T>(*mut T);

/// Const pointer: *const
///
/// We use *mut as inner data since it will be mutated by our fuzzer
#[repr(transparent)]
#[derive(Debug)]
pub struct FuzzConstPointer<T>(*mut T);

/// FrozenPointer: Always be NULL
/// 
/// We use this kind of pointer to hold filtered function pointer type 
#[repr(transparent)]
pub struct FuzzFrozenPointer<T>(*const u8, PhantomData<T>);