//! Traits for function we are fuzzing

use downcast_rs::Downcast;
use std::fmt;

use super::*;
use crate::ObjGenerate;

pub type IgnoredFnPointer = ::std::ffi::c_void;

/// Function signature
pub trait FnSignature: 'static {
    fn arg_type_names() -> Vec<&'static str>;
    fn ret_type_name() -> Option<&'static str>;
    fn canary_fn_pointer() -> Self;
}

/// Fucntion that we can fuzz
pub trait FnFuzzable: 'static + Sync + Send + Downcast {
    fn get_arg_type_names(&self) -> Vec<&'static str>;
    fn get_ret_type_name(&self) -> Option<&'static str>;
    fn eval(&self, args: &[&FuzzObject]) -> FuzzObject;
    fn add_type_gadgets(&self, gadgets: &mut ProgramGadgets);
}

downcast_rs::impl_downcast!(FnFuzzable);

macro_rules! init_fuzz_fn {
    ($($name: ident),*) => {
        init_fuzz_fn!( @internal | => $($name),* | |);
        init_fuzz_fn!( @internal unsafe | => $($name),* | |);
        init_fuzz_fn!( @internal unsafe | extern "C" => $($name),* | |);
    };
    ($($name: ident),*, ...) => {
        init_fuzz_fn!( @internal unsafe | extern "C" => $($name),* | "..." | ...);
    };
    ( @internal $($unsafe_mark:ident)? | $($abi_mark:ident)? $($abi_name:literal)? => $($name: ident),* | $($dots_literal: literal)? | $($dots: tt)?) => {

impl<T: ObjFuzzable + ObjGenerate, $($name: ObjFuzzable + ObjGenerate),*> FnSignature for $($unsafe_mark)? $($abi_mark)? $($abi_name)? fn ($($name),*$(,$dots)?) -> T {
    fn arg_type_names() -> Vec<&'static str> {
        vec![ $(std::any::type_name::<$name>(), )* $($dots_literal)?]
    }
    fn ret_type_name() -> Option<&'static str> {
        if !T::is_void() {
            return Some(std::any::type_name::<T>())
        }
        None
    }
    fn canary_fn_pointer() -> Self {
        let ptr = canary::get_canary_begin();
        unsafe { std::mem::transmute::<*const u8, Self>(ptr) }
    }
}

impl<T: ObjFuzzable + ObjGenerate + ObjectDeserialize, $($name: ObjFuzzable + ObjGenerate + ObjectDeserialize),*> FnFuzzable for $($unsafe_mark)? $($abi_mark)? $($abi_name)? fn ($($name),*$(,$dots)?) -> T {
#[allow(non_snake_case)]
fn eval(&self, args: &[&FuzzObject]) -> FuzzObject {
   let self_ = *self;
   let a: ($($name,)*) = ArgFrom::downcast(args);
   let ( $($name,)* ) = a.clone();
   let r = $($unsafe_mark)? { self_($($name),*) };
   Box::new(r)
}
fn add_type_gadgets(&self, _gadgets: &mut ProgramGadgets) {
    $(
        _gadgets.add_type::<$name>();
     )*
    _gadgets.add_type::<T>();
}
fn get_arg_type_names(&self) -> Vec<&'static str> {
    Self::arg_type_names()
}
fn get_ret_type_name(&self) -> Option<&'static str> {
   Self::ret_type_name()
}
}}}

init_fuzz_fn!();
init_fuzz_fn!(A);
init_fuzz_fn!(A, B);
init_fuzz_fn!(A, B, C);
init_fuzz_fn!(A, B, C, D);
init_fuzz_fn!(A, B, C, D, E);
init_fuzz_fn!(A, B, C, D, E, F);
init_fuzz_fn!(A, B, C, D, E, F, G);
init_fuzz_fn!(A, B, C, D, E, F, G, H);
init_fuzz_fn!(A, B, C, D, E, F, G, H, I);
init_fuzz_fn!(A, B, C, D, E, F, G, H, I, J);
init_fuzz_fn!(A, B, C, D, E, F, G, H, I, J, K);
init_fuzz_fn!(A, B, C, D, E, F, G, H, I, J, K, L);

init_fuzz_fn!(A, ...);
init_fuzz_fn!(A, B, ...);
init_fuzz_fn!(A, B, C, ...);
init_fuzz_fn!(A, B, C, D, ...);
init_fuzz_fn!(A, B, C, D, E, ...);
init_fuzz_fn!(A, B, C, D, E, F, ...);
init_fuzz_fn!(A, B, C, D, E, F, G, ...);
init_fuzz_fn!(A, B, C, D, E, F, G, H, ...);
init_fuzz_fn!(A, B, C, D, E, F, G, H, I, ...);
init_fuzz_fn!(A, B, C, D, E, F, G, H, I, J, ...);
init_fuzz_fn!(A, B, C, D, E, F, G, H, I, J, K, ...);
init_fuzz_fn!(A, B, C, D, E, F, G, H, I, J, K, L, ...);

/// Cast vector of FuzzObject to a tuple with their original types
trait ArgFrom {
    fn downcast(args: &[&FuzzObject]) -> Self;
}

impl ArgFrom for () {
    fn downcast(_args: &[&FuzzObject]) -> Self {}
}

macro_rules! impl_cast_for_single_tuple {
    ($(($type_param:ident, $tuple_index:tt),)*) => {
        impl<$($type_param),*> ArgFrom for ($($type_param,)*)
            where $($type_param: ObjFuzzable + ObjGenerate,)*
        {
            fn downcast(args: &[&FuzzObject]) -> ($($type_param,)*) {
                ( $( 
                    args.get($tuple_index).unwrap().downcast_ref::<$type_param>().map_or_else(
                    || *$type_param::cast_from(args.get($tuple_index).unwrap()), 
                    |v| v.clone()), 
                )* )
            }
        }
    };
}

macro_rules! impl_cast_for_tuples {
    (@internal [$($acc:tt,)*]) => { };
    (@internal [$($acc:tt,)*] ($type_param:ident, $tuple_index:tt), $($rest:tt,)*) => {
        impl_cast_for_single_tuple!($($acc,)* ($type_param, $tuple_index),);
        impl_cast_for_tuples!(@internal [$($acc,)* ($type_param, $tuple_index),] $($rest,)*);
    };
    ($(($type_param:ident, $tuple_index:tt),)*) => {
        impl_cast_for_tuples!(@internal [] $(($type_param, $tuple_index),)*);
    };
}

impl_cast_for_tuples! {
    (A, 0),
    (B, 1),
    (C, 2),
    (D, 3),
    (E, 4),
    (F, 5),
    (G, 6),
    (H, 7),
    (I, 8),
    (J, 9),
    (K, 10),
    (L, 11),
    (M, 12),
}

impl fmt::Debug for dyn FnFuzzable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FuzzFn")
            .field("arg", &self.get_arg_type_names())
            .field("ret", &self.get_ret_type_name())
            .finish()
    }
}
