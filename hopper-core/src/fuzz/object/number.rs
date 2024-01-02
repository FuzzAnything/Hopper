//! Mutate numbers
//! Including
//!    - mutate integers
//!    - mutate floats

use num::Float;
use num_traits::{Bounded, WrappingAdd, WrappingSub};
use rand::{distributions::Standard, prelude::*};
use std::ops::*;

use crate::{
    add_det_mutation, feedback::CmpState, log, ObjCorpus, ObjGenerate, ObjMutate, ObjectState,
};

use super::*;

macro_rules! impl_fuzz_gen {
    ( $($name:ident),* ) => {
        $(
            impl ObjGenerate for $name {
                /// Use rand to generate integer
                fn generate_new( state: &mut ObjectState) -> eyre::Result<Self> {
                    if flag::is_pilot_det() || state.mutate.borrow().is_zero_weight() {
                        return Ok(Self::default());
                    }
                    // we prefer small integers during generation
                    //if rng::likely() {
                        let v: u8 = if rng::coin() {
                            rng::gen_range(0..=16)
                        } else {
                            rng::gen_range(0..=255)
                        };
                        return Ok(v as $name);
                    //}
                    //Ok(rng::gen())
                }
            }
       )*
    }
}

impl_fuzz_gen!(u16, u32, u64, u128, usize);

macro_rules! impl_fuzz_gen_neg {
    ( $($name:ident),* ) => {
        $(
            impl ObjGenerate for $name {
                /// Use rand to generate integer
                fn generate_new( state: &mut ObjectState) -> eyre::Result<Self> {
                    if flag::is_pilot_det() || state.mutate.borrow().is_zero_weight() {
                        return Ok(Self::default());
                    }
                    // we prefer small integers during generation
                    //if rng::likely() {
                        let v: i8 = if rng::coin() {
                            rng::gen_range(-4..=12)
                        } else {
                            rng::gen_range(-12..=127)
                        };
                        return Ok(v as $name);
                    //}
                    //Ok(rng::gen())
                }
            }
       )*
    }
}

impl_fuzz_gen_neg!(i16, i32, i64, i128, isize);

impl ObjGenerate for bool {
    /// Use rand to generate integer
    fn generate_new(_state: &mut ObjectState) -> eyre::Result<Self> {
        Ok(rng::gen())
    }
}

macro_rules! impl_fuzz_gen_byte {
    ( $($name:ident),* ) => {
        $(
            impl ObjGenerate for $name {
                /// Use rand to generate integer
                fn generate_new( state: &mut ObjectState) -> eyre::Result<Self> {
                    if flag::is_pilot_det() || state.mutate.borrow().is_zero_weight() {
                        return Ok(Self::default());
                    }
                    Ok(rng::gen())
                }
            }
       )*
    }
}

impl_fuzz_gen_byte!(u8, i8, char);

impl ObjGenerate for f32 {
    fn generate_new(state: &mut ObjectState) -> eyre::Result<Self> {
        if flag::is_pilot_det() || state.mutate.borrow().is_zero_weight() {
            return Ok(Self::default());
        }
        Ok(rng::gen_range(-8.0..64.0))
    }
}

impl ObjGenerate for f64 {
    fn generate_new(state: &mut ObjectState) -> eyre::Result<Self> {
        if flag::is_pilot_det() || state.mutate.borrow().is_zero_weight() {
            return Ok(Self::default());
        }
        Ok(rng::gen_range(-8.0..64.0))
    }
}

macro_rules! impl_int_mut {
    (@cmp $name:ident) => {};
    ( $($name:ident),* ) => {
        $(
            impl ObjMutate for $name {
                fn det_mutate(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
                    if let Some(op) = do_det(self, state)? {
                        return Ok(state.as_mutate_operator(op));
                    }
                    Ok(MutateOperator::nop())
                }
                fn mutate(&mut self,  state: &mut ObjectState) -> eyre::Result<MutateOperator> {
                    log!(trace, "mutate number at field: {:?}", state.get_location_fields());
                    // Random stage
                    let op = match rng::gen_range(0..10) {
                        0..=1 => bit_flip(self),
                        2..=3 => flip(self),
                        4..=6 => arithmetic(self),
                        7 => set_corpus(self),
                        8 => random_value(self),
                        _ => cmp_var(self, state),
                    };
                    log!(trace, "random operation selected: {:?}", op);
                    Ok(state.as_mutate_operator(op))
                }
                fn mutate_by_op(&mut self, _state: &mut ObjectState, keys: &[FieldKey], op: &MutateOperation) -> eyre::Result<()> {
                    if keys.len() > 0  && !(keys.len() == 1 && keys[0] == FieldKey::Index(0)) {
                        crate::log!(error, "keys: {:?}, op: {:?}", keys, op);
                        unimplemented!()
                    }
                    match op {
                        MutateOperation::IntBitFlip{ index } => { bit_flip_at(self, *index); },
                        MutateOperation::IntFlip{ indices } => { flip_at(self, indices.clone()); },
                        MutateOperation::IntAdd { change } => { add(self, *change); },
                        MutateOperation::IntSub { change } => { sub(self, *change); },
                        MutateOperation::IntSet { val } => {
                            let v: Self = val.as_constant();
                            if *self != v {
                                *self = v;
                            } else {
                                flag::set_refine_suc(false);
                            }
                        },
                        MutateOperation::IntGet  => { flag::set_tmp_u64(*self as u64) },
                        MutateOperation::IntCmp { val } => { *self = Self::from_u64(*val); },
                        MutateOperation::IntRandom { val } => { *self = Self::from_u64(*val); },
                        MutateOperation::IntVariance { val } => { *self = Self::from_u64(*val); },
                        MutateOperation::Corpus { index } => { set_corpus_at(self, *index); },
                        MutateOperation::IntRange { min, max } => {
                            let min_val: Self = min.as_constant();
                            let max_val: Self = max.as_constant();
                            if *self >= max_val || *self < min_val {
                                if max_val <= min_val {
                                    *self = num::cast(0).unwrap();
                                } else {
                                    *self = rng::gen_range(min_val..max_val);
                                }
                            } else {
                                flag::set_refine_suc(false);
                            }
                        },
                        _ => {
                            eyre::bail!("unsuppported operator for {}: {op:?}", stringify!($name));
                        }
                    }
                    Ok(())
                }
            }
            impl DetMutate for $name {
                fn det_mutateion_steps() -> Vec<Box<dyn DetMutateStep>> {
                    let mut steps: Vec<Box<dyn DetMutateStep>> = vec![];
                    // add and sub 1, 2
                    for i in 1..=2 {
                        add_det_mutation!(steps, "add", |n: $name| (add(n, i), DetAction::Next));
                        add_det_mutation!(steps, "sub", |n: $name| (sub(n, i), DetAction::Next));
                    }
                    // bit flips
                    let num_bits = (std::mem::size_of::<Self>() * 8) as u8;
                    for i in (0..num_bits).rev() {
                        add_det_mutation!(steps, "bit_flip", |n: $name, s| {
                            let op = bit_flip_at(n, i);
                            // if it is in a list, we just flip once
                            if let FieldKey::Index{..} = &s.key {
                                return (op, DetAction::Last)
                            }
                            (op, DetAction::Next)
                        });
                    }
                    // corpus
                    for i in 0..$name::corpus_size() {
                        add_det_mutation!(steps, "corpus", |n: $name| (set_corpus_at(n, i), DetAction::Next));
                    }
                    // cmp
                    add_det_mutation!(steps, "cmp", |n: $name, s| {
                        let cmps = &mut s.mutate.borrow_mut().related_cmps;
                        if let Some(det_cmp) = cmps.iter_mut().find(|c| c.det) {
                            log!(trace, "cmp det: {det_cmp:?}");
                            det_cmp.det = false;
                            (set_cmp(n, det_cmp, s, 0), DetAction::Keep)
                        } else {
                            (MutateOperation::Nop, DetAction::Finish)
                        }
                    });
                    steps
                }
            }

       )*
    }
}

impl_int_mut!(u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, usize, isize);

macro_rules! impl_fuzz_mut_cast {
    ($name:ident, $cast:ident) => {
        impl ObjMutate for $name {
            fn det_mutate(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
                let casted = unsafe { &mut *(self as *mut $name as *mut $cast) };
                casted.det_mutate(state)
            }
            fn mutate(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
                let casted = unsafe { &mut *(self as *mut $name as *mut $cast) };
                casted.mutate(state)
            }
            fn mutate_by_op(
                &mut self,
                state: &mut ObjectState,
                keys: &[FieldKey],
                op: &MutateOperation,
            ) -> eyre::Result<()> {
                let casted = unsafe { &mut *(self as *mut $name as *mut $cast) };
                casted.mutate_by_op(state, keys, op)
            }
        }
    };
}

// Cast them for U* and do mutating
impl_fuzz_mut_cast!(char, u8);

impl ObjMutate for bool {
    fn mutate(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        *self = !*self;
        Ok(state.as_mutate_operator(MutateOperation::FlipBool))
    }
    fn mutate_by_op(
        &mut self,
        _state: &mut ObjectState,
        keys: &[FieldKey],
        op: &MutateOperation,
    ) -> eyre::Result<()> {
        if !keys.is_empty() {
            unimplemented!()
        }
        match op {
            MutateOperation::FlipBool => {
                *self = !*self;
            }
            _ => {
                unimplemented!();
            }
        }
        Ok(())
    }
}

macro_rules! impl_float_mut {
    ( $($name:ident),* ) => {
        $(
impl ObjMutate for $name {
    fn det_mutate(&mut self,  state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        if let Some(op) = do_det(self, state)? {
            return Ok(state.as_mutate_operator(op));
        }
        Ok(MutateOperator::nop())
    }
    fn mutate(
        &mut self,
        state: &mut ObjectState,
    ) -> eyre::Result<MutateOperator> {
        // Random stage
        let op = if rng::rarely() {
            set_corpus(self)
        } else if rng::coin() {
            let change = rng::gen_range(-1.0..1.0);
            float_add(self, change)
        } else {
            let val = Self::generate_new( state)? as f64;
            float_set(self, val)
        };
        Ok(state.as_mutate_operator(op))
    }
    fn mutate_by_op(&mut self,  _state: &mut ObjectState, keys: &[FieldKey], op: &MutateOperation) -> eyre::Result<()> {
        if keys.len() > 0 {
            unimplemented!()
        }
        match op {
            MutateOperation::FloatAdd { change } => {  float_add(self, *change); },
            MutateOperation::FloatNew { val } => {  float_set(self, *val); },
            MutateOperation::Corpus { index } => { set_corpus_at(self, *index); },
            _ => {
                unimplemented!();
            }
        }
        Ok(())
    }
}

impl DetMutate for $name {
    fn det_mutateion_steps() -> Vec<Box<dyn DetMutateStep>> {
        let mut steps: Vec<Box<dyn DetMutateStep>> = vec![];
        let size = $name::corpus_size();
        if size > 0 {
            for i in 0..size - 1 {
                add_det_mutation!(steps, "corpus", |n: $name| (set_corpus_at(n, i), DetAction::Next ));
            }
            add_det_mutation!(steps, "corpus_last", |n: $name| (set_corpus_at(n, size - 1), DetAction::Finish));
        }
        steps
    }
}
       )*
    }
}

impl_float_mut!(f32, f64);

/// Flip a single bit in the given number.
pub fn bit_flip<T>(num: &mut T) -> MutateOperation
where
    T: BitXor<Output = T> + IntCast + Copy,
{
    let num_bits = (std::mem::size_of::<T>() * 8) as u8;
    let idx: u8 = rng::gen_range(0..num_bits);
    bit_flip_at(num, idx)
}

fn bit_flip_at<T>(num: &mut T, idx: u8) -> MutateOperation
where
    T: BitXor<Output = T> + IntCast + Copy,
{
    log!(trace, "xoring bit at {}-th ", idx);
    *num = (*num) ^ T::from_u128(1_u128 << idx);
    MutateOperation::IntBitFlip { index: idx }
}

/// Flip more than 1 bit in this number. This is a flip potentially up to
/// the max bits in the number
pub fn flip<T>(num: &mut T) -> MutateOperation
where
    T: BitXor<Output = T> + IntCast + Copy,
{
    let num_bits = (std::mem::size_of::<T>() * 8) as u8;
    let bits_to_flip = rng::gen_range(1..=num_bits) as usize;
    // 64 is chosen here as it's the the max primitive size (in bits) that we support
    // we choose to do this approach over a vec to avoid an allocation
    assert!(num_bits <= 64);
    let bit_indices = rng::choose_multiple(0..num_bits, bits_to_flip);
    flip_at(num, bit_indices)
}

fn flip_at<T>(num: &mut T, bit_indices: Vec<u8>) -> MutateOperation
where
    T: BitXor<Output = T> + IntCast + Copy,
{
    log!(trace, "flip bits, indices: {:?}", bit_indices);
    for &idx in &bit_indices {
        *num = (*num) ^ T::from_u128(1_u128 << idx);
    }
    MutateOperation::IntFlip {
        indices: bit_indices,
    }
}

/// Perform a simple arithmetic operation on the number (+ or -)
pub fn arithmetic<T>(num: &mut T) -> MutateOperation
where
    T: IntCast + Copy + WrappingAdd<Output = T> + WrappingSub<Output = T>,
{
    let change: u64 = rng::gen_range(1..=16);
    if rng::coin() {
        add(num, change)
    } else {
        sub(num, change)
    }
}

fn add<T>(num: &mut T, change: u64) -> MutateOperation
where
    T: IntCast + Copy + WrappingAdd<Output = T>,
{
    log!(trace, "adding {}", change);
    *num = num.wrapping_add(&T::from_u64(change));
    MutateOperation::IntAdd { change }
}

fn sub<T>(num: &mut T, change: u64) -> MutateOperation
where
    T: IntCast + Copy + WrappingSub<Output = T>,
{
    log!(trace, "subtracting {}", change);
    *num = num.wrapping_sub(&T::from_u64(change));
    MutateOperation::IntSub { change }
}

/// Set num as corpus' value
pub fn set_corpus<T: ObjCorpus>(num: &mut T) -> MutateOperation {
    let n = T::corpus_size();
    if n > 0 {
        let index = rng::gen_range(0..n);
        set_corpus_at(num, index)
    } else {
        MutateOperation::Nop
    }
}

pub fn set_corpus_at<T: ObjCorpus>(num: &mut T, index: usize) -> MutateOperation {
    log!(trace, "set corpus {}", index);
    if let Some(v) = T::get_interesting_value(index) {
        *num = v;
    }
    MutateOperation::Corpus { index }
}

pub fn random_value<T>(num: &mut T) -> MutateOperation
where
    Standard: Distribution<T>,
    T: IntCast + Copy + std::fmt::Debug,
{
    let val: T = rng::gen();
    *num = val;
    MutateOperation::IntRandom { val: val.as_u64() }
}

fn is_u8(n: u64) -> bool {
    n < 256
}

fn is_i8(n: u64, size: usize) -> bool {
    if size == 1 {
        true
    } else if size == 2 {
        let n = n as i16;
        (-128..128).contains(&n)
    } else if size == 4 {
        let n = n as i32;
        (-128..128).contains(&n)
    } else {
        let n = n as i64;
        (-128..128).contains(&n)
    }
}

fn set_cmp<T>(
    num: &mut T,
    cmp_state: &CmpState,
    object_state: &ObjectState,
    bias: i32,
) -> MutateOperation
where
    T: IntCast + Copy + std::fmt::Debug,
{
    let op = cmp_state.op.borrow();
    let mut size = op.size as usize;
    let mut operand: u64 = if cmp_state.affect_left {
        op.operand2
    } else {
        op.operand1
    };
    operand = operand.saturating_add_signed(bias as i64);
    let type_size = std::mem::size_of::<T>();
    // type mismatch, e.g char is casted to int
    if type_size == 1 && size > 1
        && ((is_u8(op.operand1) && is_u8(op.operand2))
            || (is_i8(op.operand1, size) && is_i8(op.operand2, size)))
    {
        crate::log!(trace, "type mismatch, size should be 1");
        size = 1;
    }
    // for vec<u8> or vec<i8>
    if type_size == 1 && type_size < size {
        if let FieldKey::Index(i) = object_state.key {
            crate::log!(trace, "cast num to size {} for det", size);
            let len = object_state.get_parent().unwrap().children.len();
            if i + size <= len {
                match size {
                    2 => {
                        let ptr = num as *mut T as *mut u16;
                        unsafe { ptr.write_unaligned(u16::from_u64(operand)) };
                    }
                    4 => {
                        let ptr = num as *mut T as *mut u32;
                        unsafe { ptr.write_unaligned(u32::from_u64(operand)) };
                    }
                    8 => {
                        let ptr = num as *mut T as *mut u64;
                        unsafe { ptr.write_unaligned(u64::from_u64(operand)) };
                    }
                    _ => {
                        *num = T::from_u64(operand);
                    }
                }
            }
        }
    } else {
        *num = T::from_u64(operand);
    }
    log!(trace, "cmp set: {operand}");
    if bias > 0 {
        log!(trace, "add bias: {bias}");
    }
    MutateOperation::IntCmp { val: operand }
}

impl IrEntry {
    pub fn as_constant<
        T: Bounded + IntCast + Copy + WrappingAdd<Output = T> + WrappingSub<Output = T>,
    >(
        &self,
    ) -> T {
        match self {
            Self::Min(off) => T::min_value().wrapping_add(&T::from_u64(*off as u64)),
            Self::Max(off) => T::max_value().wrapping_sub(&T::from_u64(*off as u64)),
            Self::Constant(val) => T::from_u64(*val),
            _ => T::from_u64(0),
        }
    }
}

/// Set value as compare bytes or corpus, and add some mathematic variance
fn cmp_var<T>(num: &mut T, state: &ObjectState) -> MutateOperation
where
    T: IntCast
        + ObjCorpus
        + Copy
        + WrappingAdd<Output = T>
        + WrappingSub<Output = T>
        + std::fmt::Debug,
{
    if rng::likely() {
        if let Some(cmp_state) = rng::choose_iter(state.mutate.borrow().related_cmps.iter()) {
            let mut bias = 0;
            if rng::likely() {
                bias = rng::gen_range(-5..=5);
            }
            crate::log_trace!("cmpvar use cmp, bias: {bias}");
            return set_cmp(num, cmp_state, state, bias);
        }
    }
    crate::log_trace!("cmpvar use corpus");
    let _ = set_corpus(num);
    let _arith_op = arithmetic(num);
    MutateOperation::IntVariance { val: num.as_u64() }
}

fn float_add<T>(num: &mut T, change: f32) -> MutateOperation
where
    T: Float,
{
    log!(trace, "float arith: {}", change);
    *num = num.mul_add(num::cast(1.0).unwrap(), num::cast(change).unwrap());
    MutateOperation::FloatAdd { change }
}

fn float_set<T>(num: &mut T, val: f64) -> MutateOperation
where
    T: Float,
{
    log!(trace, "float new: {}", val);
    *num = num::cast(val).unwrap();
    MutateOperation::FloatNew { val }
}

pub trait IntCast {
    fn from_u64(val: u64) -> Self;
    fn from_u128(val: u128) -> Self;
    fn as_u64(&self) -> u64;
    fn as_u128(&self) -> u128;
}

macro_rules! impl_int_cast_unsign {
    ( $($name:ident),* ) => {
    $(
        impl IntCast for $name {
            fn from_u64(val: u64) -> Self {
               val as Self
            }
            fn from_u128(val: u128) -> Self {
                val as Self
            }
            fn as_u64(&self) -> u64 {
                *self as u64
            }
            fn as_u128(&self) -> u128 {
                *self as u128
            }
        }
    )*
    }
}
impl_int_cast_unsign!(u8, u16, u32, u64, u128, usize);

macro_rules! impl_int_cast_sign {
    ($name:ident, $cast:ident) => {
        impl IntCast for $name {
            fn from_u64(val: u64) -> Self {
                val as $cast as Self
            }
            fn from_u128(val: u128) -> Self {
                val as $cast as Self
            }
            fn as_u64(&self) -> u64 {
                *self as $cast as u64
            }
            fn as_u128(&self) -> u128 {
                *self as $cast as u128
            }
        }
    };
}

impl_int_cast_sign!(i8, u8);
impl_int_cast_sign!(i16, u16);
impl_int_cast_sign!(i32, u32);
impl_int_cast_sign!(i64, u64);
impl_int_cast_sign!(i128, u128);
impl_int_cast_sign!(isize, usize);

#[test]
fn test_write_bytes() {
    use crate::feedback::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    let val = 12300_u16;
    println!("{:?}", val.to_le_bytes());
    println!("{:?}", val.to_be_bytes());

    let val_m = 12349_u16;
    println!("val_m: {:?}", val_m.to_le_bytes());

    /*
    let mut val2 = 0_u16;
    val2 = u16::from_u64(12300_u64);
    println!("val2: {val2}");
    */

    let val3 = -100000000_i32;
    println!("val_3({}): {:?}", val3 as u32, val3.to_le_bytes());
    let mut buf = vec![0_i8; 20];
    let cmp_op = CmpOperation {
        operand1: 12300,
        operand2: 0x7788,
        id: 0,
        size: 2,
        ty: 0,
        stmt_index: 0,
        state: 0,
    };
    let cmp_state = CmpState {
        id: 0,
        op: Rc::new(RefCell::new(cmp_op)),
        affect_left: false,
        det: true,
    };
    let mut object_state = ObjectState::root("test", "CmpState");
    for i in 0..buf.len() {
        object_state.add_child(FieldKey::Index(i), "usize");
    }
    println!("buf ptr: {:?}", buf.as_slice().as_ptr());
    set_cmp(&mut buf[1], &cmp_state, &object_state.children[1], 0);
    println!("buf: {buf:?}");

    cmp_state.op.borrow_mut().operand1 = 987654325;
    cmp_state.op.borrow_mut().size = 4;
    set_cmp(&mut buf[4], &cmp_state, &object_state.children[4], 0);
    println!("buf: {buf:?}");

    cmp_state.op.borrow_mut().operand1 = 4194967296;
    cmp_state.op.borrow_mut().size = 4;
    set_cmp(&mut buf[10], &cmp_state, &object_state.children[10], 0);
    println!("buf: {buf:?}");
}
