//! Mutate sequence, including vector and array

use crate::{
    add_det_mutation, buf::BufMutate, config, utils, ObjFuzzable, ObjValue, ObjectDeserialize,
    ObjectState,
};

use std::{fmt::Debug, mem::MaybeUninit};

use super::*;

impl<T: ObjGenerate + ObjFuzzable + ObjectDeserialize, const N: usize> ObjGenerate for [T; N] {
    /// Generate value for each element in the arrays
    fn generate_new(state: &mut ObjectState) -> eyre::Result<Self> {
        if N == 0 {
            // opaque structure
            unsafe {
                return Ok(std::mem::zeroed());
            }
        }
        // eyre::ensure!(N > 0, "fail to generate zero-sized array!");
        let mut output: MaybeUninit<[T; N]> = MaybeUninit::uninit();
        let arr_ptr = output.as_mut_ptr() as *mut T;
        for i in 0..N {
            let element = create_element_for_slice::<T>(state, i)?;
            unsafe {
                arr_ptr.add(i).write(element);
            }
        }
        // add terminator
        if T::is_primitive() {
            let end = rng::gen_range(0..N) as isize;
            unsafe {
                let zero: T = std::mem::zeroed();
                arr_ptr.offset(end).write(zero);
            }
        }
        Ok(unsafe { output.assume_init() })
    }
}

impl<T: ObjGenerate + ObjFuzzable> ObjGenerate for Vec<T> {
    /// Generate value for each element in the vector
    fn generate_new(state: &mut ObjectState) -> eyre::Result<Self> {
        let len = if T::is_primitive()
            || (rng::rarely() && !flag::is_pilot_det() && std::mem::size_of::<T>() < 1024)
        {
            rng::gen_range(config::MIN_VEC_LEN..=config::MAX_VEC_LEN)
        } else {
            1
        };
        let mut list = vec![];
        for i in 0..len {
            let element = create_element_for_slice::<T>(state, i)?;
            list.push(element);
        }
        add_vec_terminator(&mut list, state);
        Ok(list)
    }
}

/// Both vec and array can be viewed by a slice, then do some mutation
impl<T: ObjFuzzable + ObjGenerate> ObjMutate for [T] {
    fn mutate(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        if self.is_empty() {
            return Ok(MutateOperator::nop());
        }
        // only select one in slice
        let idx = weight::choose_weighted_by_state(state)
            .unwrap_or_else(|| rng::gen_range(0..self.len()));
        // UNUSED: if it is not primitive, we likely to mutate its first element.
        // we do not use this since we have minimized the arguments.
        // if !T::is_primitive() && rng::rarely() {
        //     idx = 0;
        // }
        self[idx].mutate(state.get_child_mut(idx)?)
    }

    fn mutate_by_op(
        &mut self,
        state: &mut ObjectState,
        keys: &[FieldKey],
        op: &MutateOperation,
    ) -> eyre::Result<()> {
        if !keys.is_empty() {
            let field = &keys[0];
            let index = field.as_usize()?;
            if index < self.len() {
                let sub_state = state.get_child_mut(field)?;
                self[index].mutate_by_op(sub_state, &keys[1..], op)?;
            }
        } else {
            match op {
                MutateOperation::Nop => {}
                _ => {
                    if !self.is_empty() {
                        let sub_state = state.get_child_mut(&FieldKey::Index(0))?;
                        self[0].mutate_by_op(sub_state, &[], op)?;
                        return Ok(());
                    }
                    eyre::bail!("op: {:?} is not support", op);
                }
            }
        }
        Ok(())
    }
}

impl<T: ObjFuzzable + ObjGenerate + ObjectDeserialize, const N: usize> ObjMutate for [T; N] {
    // Deterministic steps:
    //  - should deterministic mutate chilren first,
    //  - then run the steps that holded by itself
    fn det_mutate(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        if N == 0 {
            return Ok(MutateOperator::nop());
        }
        if let Some(idx) = state.get_deterministic_child_position() {
            let op = self[idx].det_mutate(state.get_child_mut(idx)?)?;
            add_arr_terminator(self);
            Ok(op)
        } else if let Some(op) = do_det(self, state)? {
            Ok(state.as_mutate_operator(op))
        } else {
            Ok(MutateOperator::nop())
        }
    }

    /// Random select an element in array and mutate it.
    fn mutate(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        if N == 0 {
            return Ok(MutateOperator::nop());
        }
        let op = self.as_mut().mutate(state)?;
        add_arr_terminator(self);
        Ok(op)
    }

    fn mutate_by_op(
        &mut self,
        state: &mut ObjectState,
        keys: &[FieldKey],
        op: &MutateOperation,
    ) -> eyre::Result<()> {
        if !keys.is_empty() {
            self.as_mut_slice().mutate_by_op(state, keys, op)?;
            add_arr_terminator(self);
            return Ok(());
        }
        match op {
            MutateOperation::Nop => {}
            MutateOperation::BufRefine { buffer } => {
                if self.len() >= buffer.len() {
                    let cur = unsafe {
                        std::slice::from_raw_parts(self.as_ptr() as *const u8, buffer.len())
                    };
                    if &cur[..buffer.len()] == buffer {
                        flag::set_refine_suc(false);
                        return Ok(());
                    }
                }
                self.assign_buf(0, buffer, state);
                if buffer.len() < self.len() {
                    self[buffer.len()] = unsafe { std::mem::zeroed() };
                }
            }
            MutateOperation::BufCmp { offset, buffer } => {
                self.assign_buf(*offset, buffer, state);
            }
            _ => {
                self.as_mut().mutate_by_op(state, keys, op)?;
                add_arr_terminator(self);
            }
        }
        Ok(())
    }
}

impl<T: ObjFuzzable + ObjGenerate> ObjMutate for Vec<T> {
    /// Deterministic steps:
    ///  - should deterministic mutate chilren first,
    ///  - then run the steps that holded by itself
    fn det_mutate(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        if T::is_opaque() {
            if state.is_deterministic() {
                state.done_deterministic();
            }
            return Ok(MutateOperator::nop());
        }
        crate::log!(trace, "det mut seq");
        remove_vec_teminator(self, state);
        let op = if let Some(idx) = state.get_deterministic_child_position() {
            crate::log!(trace, "det mut index {idx}");
            self[idx].det_mutate(state.get_child_mut(idx)?)?
        } else if let Some(det_op) = do_det(self, state)? {
            // if state.children.len() < self.len() {
            //     state.mutate.borrow_mut().deterministic = true;
            // }
            // resize state length
            while state.children.len() < self.len() {
                let _ = state.add_child_at_offset(state.children.len(), std::any::type_name::<T>());
            }
            while state.children.len() > self.len() {
                state.children.pop();
            }
            state.as_mutate_operator(det_op)
        } else {
            MutateOperator::nop()
        };
        add_vec_terminator(self, state);
        Ok(op)
    }
    /// Random select an element in the vector and mutate it.
    fn mutate(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        if T::is_opaque() {
            return Ok(MutateOperator::nop());
        }
        remove_vec_teminator(self, state);
        let use_resize = rng::rarely() && !crate::is_input_only();
        if use_resize {
            let resize_op = resize_vec(self, state)?;
            assert_eq!(state.children.len(), self.len());
            if !resize_op.is_nop() {
                add_vec_terminator(self, state);
                return Ok(state.as_mutate_operator(resize_op));
            }
        }
        let op = if self.len() > 8 && utils::is_byte(std::any::type_name::<T>()) {
            self.mutate_buf(state)?
        } else {
            self.as_mut_slice().mutate(state)?
        };
        add_vec_terminator(self, state);
        Ok(op)
    }
    /// Mutate by op
    fn mutate_by_op(
        &mut self,
        state: &mut ObjectState,
        keys: &[FieldKey],
        op: &MutateOperation,
    ) -> eyre::Result<()> {
        remove_vec_teminator(self, state);
        if !keys.is_empty() {
            self.as_mut_slice().mutate_by_op(state, keys, op)?;
            add_vec_terminator(self, state);
            return Ok(());
        }
        match op {
            MutateOperation::Nop => {}
            MutateOperation::BufRefine { buffer } => {
                self.assign_buf(0, buffer, state);
                let cut_len = self.len() - buffer.len();
                if cut_len > 0 {
                    let offset = buffer.len();
                    vec_del_elements(self, state, offset, cut_len)?;
                }
            }
            MutateOperation::VecPad {
                len,
                zero,
                rng_state,
            } => {
                let mut start = self.len();
                if *len > start {
                    if T::is_primitive() {
                        start += 1;
                    }
                    let diff = len - start;
                    crate::log!(trace, "pad diff: {diff}");
                    let _tmp_rng = rng::TempRngGuard::temp_use(rng_state);
                    if *zero && T::is_primitive() {
                        let size = std::mem::size_of::<T>();
                        let buf = vec![0; diff * size];
                        self.assign_buf(start * size, &buf, state);
                    } else {
                        vec_add_elements(self, state, start, diff)?;
                    }
                    eyre::ensure!(self.len() >= len - 1, "resize to specific length");
                } else {
                    flag::set_refine_suc(false);
                }
            }
            MutateOperation::BufCmp { offset, buffer } => {
                self.assign_buf(*offset, buffer, state);
            }
            MutateOperation::BufSeed { index } => {
                let ident = state.key.as_str().unwrap();
                if let Some(buf) = buf::get_buf_seeds(*index, ident) {
                    self.assign_buf(0, buf, state);
                }
            }
            MutateOperation::VecAdd {
                offset,
                len,
                rng_state,
            } => {
                let _tmp_rng = rng::TempRngGuard::temp_use(rng_state);
                vec_add_elements(self, state, *offset, *len)?;
            }
            MutateOperation::VecDel { offset, len } => {
                vec_del_elements(self, state, *offset, *len)?;
            }
            _ => {
                if utils::is_byte(std::any::type_name::<T>()) {
                    self.mutate_buf_by_op(state, keys, op)?;
                } else {
                    self.as_mut_slice().mutate_by_op(state, keys, op)?;
                }
            }
        }
        add_vec_terminator(self, state);
        Ok(())
    }
}

impl<T: ObjFuzzable + ObjGenerate + ObjectDeserialize, const N: usize> DetMutate for [T; N] {
    fn det_mutateion_steps() -> Vec<Box<dyn DetMutateStep>> {
        let mut steps: Vec<Box<dyn DetMutateStep>> = vec![];
        add_det_mutation!(steps, "buf_det", |arr: [T; N], state| {
            assign_buf_for_cmp_fn_ptr(arr, state)
        });
        steps
    }
}

impl<T: ObjFuzzable + ObjGenerate> DetMutate for Vec<T> {
    fn det_mutateion_steps() -> Vec<Box<dyn DetMutateStep>> {
        let mut steps: Vec<Box<dyn DetMutateStep>> = vec![];
        add_det_mutation!(steps, "buf_det", |arr: Vec<T>, state| {
            // try seeds
            if utils::is_byte(std::any::type_name::<T>()) {
                let index = state.mutate.borrow().get_mutation();
                crate::log!(trace, "assgin seed buf: {index}");
                if let Some(buf) = buf::get_buf_seeds(index, state.key.as_str().unwrap()) {
                    arr.assign_buf(0, buf, state);
                    return (MutateOperation::BufSeed { index }, DetAction::Keep);
                }
            }
            assign_buf_for_cmp_fn_ptr(arr, state)
        });
        steps
    }
}

/// Assign collected buffer in compare functions, and assign to its used pointer
fn assign_buf_for_cmp_fn_ptr<T: AssignBuf + ObjGenerate + Debug>(
    list: &mut T,
    state: &mut ObjectState,
) -> (MutateOperation, DetAction) {
    let mut cmp_buf = None;
    {
        let cmps = &mut state.mutate.borrow_mut().cmp_bufs;
        if let Some(det_cmp) = cmps.iter_mut().find(|c| c.det) {
            det_cmp.det = false;
            cmp_buf = Some(det_cmp.clone())
        }
    }
    if let Some(cmp) = cmp_buf {
        crate::log!(
            trace,
            "assgin buf ({}) from cmp: {:?} <- {:?}",
            cmp.offset,
            list,
            cmp.buf.as_slice()
        );
        list.assign_buf(cmp.offset, cmp.buf.as_slice(), state);
        let op = MutateOperation::BufCmp {
            offset: cmp.offset,
            buffer: cmp.buf,
        };
        return (op, DetAction::Keep);
    }
    (MutateOperation::Nop, DetAction::Finish)
}

/// How to assgin a buffer to a list : Vec or Array
trait AssignBuf {
    fn assign_buf(&mut self, offset: usize, buf: &[u8], state: &mut ObjectState);
    fn zeroed(&mut self);
}

impl<T: ObjGenerate + ObjValue, const N: usize> AssignBuf for [T; N] {
    fn assign_buf(&mut self, offset: usize, buf: &[u8], _state: &mut ObjectState) {
        let len = buf.len() / std::mem::size_of::<T>();
        if len == 0 {
            return;
        }
        let buf = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const T, len) };
        let offset = offset / std::mem::size_of::<T>();
        if offset < N {
            let min = len.min(N - offset);
            self[offset..offset + min].clone_from_slice(&buf[..min]);
            // teminator
            if offset + min < N && T::is_primitive() && !self[offset + min - 1].is_zero() {
                self[offset + min] = unsafe { std::mem::zeroed() };
            }
        }
    }

    fn zeroed(&mut self) {
        // ATTN: zero is unsafe
        for v in self {
            *v = unsafe { std::mem::zeroed() };
        }
    }
}

impl<T: ObjGenerate + ObjValue> AssignBuf for Vec<T> {
    fn assign_buf(&mut self, offset: usize, buf: &[u8], state: &mut ObjectState) {
        let buf_len = buf.len() / std::mem::size_of::<T>();
        if buf_len == 0 {
            return;
        }
        let offset = offset / std::mem::size_of::<T>();
        let buf = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const T, buf_len) };
        for (i, v) in buf.iter().enumerate() {
            if offset + i < self.len() {
                self[offset + i] = v.clone();
            } else {
                self.push(v.clone());
                state.add_child(state.children.len(), std::any::type_name::<T>());
            }
        }
    }

    fn zeroed(&mut self) {
        for v in self {
            *v = unsafe { std::mem::zeroed() };
        }
    }
}

/// Create element for slice
fn create_element_for_slice<T: ObjGenerate + ObjValue>(
    state: &mut ObjectState,
    offset: usize,
) -> eyre::Result<T> {
    let _ = state.add_child_at_offset(state.children.len(), std::any::type_name::<T>());
    T::generate_new(&mut state.children[offset])
}

fn add_arr_terminator<T: ObjFuzzable + ObjGenerate>(arr: &mut [T]) {
    if T::is_primitive() {
        let has_zero = arr.iter().any(|v| v.is_zero());
        if !has_zero {
            let zero: T = unsafe { std::mem::zeroed() };
            let index = arr.len() - 1;
            arr[index] = zero;
        }
    }
}

pub fn remove_vec_teminator<T: ObjGenerate + ObjFuzzable>(
    list: &mut Vec<T>,
    state: &mut ObjectState,
) {
    if T::is_primitive() {
        list.pop();
        state.children.pop();
    }
}

pub fn add_vec_terminator<T: ObjGenerate + ObjFuzzable>(
    list: &mut Vec<T>,
    state: &mut ObjectState,
) {
    if T::is_primitive() {
        let zero: T = unsafe { std::mem::zeroed() };
        state.add_child(state.children.len(), std::any::type_name::<T>());
        list.push(zero);
    }
}

pub fn resize_vec<T: ObjFuzzable + ObjGenerate>(
    list: &mut Vec<T>,
    state: &mut ObjectState,
) -> eyre::Result<MutateOperation> {
    let len = rng::gen_range(1..=config::MAX_VEC_LEN / 2);
    let can_add = list.len() + len <= config::MAX_VEC_LEN || T::is_primitive();
    let can_del = list.len() > len;
    if rng::coin() && can_del {
        let offset = rng::gen_range(0..list.len() - len);
        vec_del_elements(list, state, offset, len)?;
        Ok(MutateOperation::VecDel { offset, len })
    } else if can_add {
        let offset = rng::gen_range(0..=list.len());
        let rng_state = rng::save_rng_state();
        vec_add_elements(list, state, offset, len)?;
        Ok(MutateOperation::VecAdd {
            offset,
            len,
            rng_state,
        })
    } else {
        Ok(MutateOperation::Nop)
    }
}

pub fn vec_insert_chunk<T: ObjFuzzable + ObjGenerate>(
    list: &mut Vec<T>,
    state: &mut ObjectState,
    offset: usize,
    chunk: &[u8],
    is_insert: bool,
) -> eyre::Result<()> {
    if is_insert {
        vec_add_elements(list, state, offset, chunk.len())?;
    }
    list.assign_buf(offset, chunk, state);
    Ok(())
}

fn vec_add_elements<T: ObjFuzzable + ObjGenerate>(
    list: &mut Vec<T>,
    state: &mut ObjectState,
    offset: usize,
    len: usize,
) -> eyre::Result<()> {
    let mut offset = offset;
    if offset > list.len() {
        offset = list.len();
    }
    crate::log!(trace, "vec add {} elements at {}", len, offset);
    /*
    if len > 10000 {
        crate::log!(trace, "skip adding, length is {len}");
        return Ok(());
    }
    */
    // copy all elements from exist ones
    let mut copy_all = false;
    if rng::rarely() {
        copy_all = true;
    }
    for i in 0..len {
        let off = offset + i;
        if T::is_primitive() {
            let _ = state.add_child_at_offset(state.children.len(), std::any::type_name::<T>());
        }
        let element = if !list.is_empty() && copy_all && rng::coin() {
            // use exist one
            let chosed = rng::gen_range(0..list.len());
            if !T::is_primitive() {
                state.dup_child_state(chosed, off);
            }
            list[chosed].clone()
        } else {
            if !T::is_primitive() {
                let _ = state.add_child_at_offset(off, std::any::type_name::<T>());
            }
            T::generate_new(&mut state.children[off])?
        };
        list.insert(off, element);
    }
    crate::log!(
        trace,
        "new length: {} / {}",
        list.len(),
        state.children.len()
    );
    eyre::ensure!(state.children.len() == list.len(), "length consistent");
    if !T::is_primitive() {
        state.resort_children_indices();
    }
    Ok(())
}

fn vec_del_elements<T: ObjFuzzable + ObjGenerate>(
    list: &mut Vec<T>,
    state: &mut ObjectState,
    offset: usize,
    len: usize,
) -> eyre::Result<()> {
    crate::log!(trace, "vec del {} elements at {}", len, offset);
    let mut offset = offset;
    if list.len() > len && offset >= list.len() {
        offset = list.len() - len;
    }
    for _ in 0..len {
        if list.len() <= offset || list.len() == 1 {
            break;
        }
        let _ = list.remove(offset);
        if T::is_primitive() {
            let _ = state.children.pop();
        } else {
            state.children.remove(offset);
        }
        eyre::ensure!(list.len() == state.children.len(), "consistent length");
    }
    if !T::is_primitive() {
        state.resort_children_indices();
    }
    Ok(())
}

#[cfg(test)]
fn assert_seq_state(state: &ObjectState, n: usize) {
    assert_eq!(state.children.len(), n);
    for (i, s) in state.children.iter().enumerate() {
        if let FieldKey::Index(si) = s.key {
            assert_eq!(i, si);
        }
    }
}

#[test]
fn test_arr_gen_mutate() {
    // generate
    let mut state = ObjectState::root("test", "[u8; 10]");
    let mut arr = <[u8; 10]>::generate_new(&mut state).unwrap();
    println!("arr: {arr:?}");
    assert_eq!(state.children.len(), arr.len());
    assert!(arr.iter().any(|i| *i == 0));
    // mutate
    for _ in 0..200 {
        let op = arr.mutate(&mut state).unwrap();
        assert!(!op.is_nop());
        assert!(arr.iter().any(|i| *i == 0));
        assert_seq_state(&state, arr.len());
    }
    for _ in 0..200 {
        arr.det_mutate(&mut state).unwrap();
        assert!(arr.iter().any(|i| *i == 0));
        assert_seq_state(&state, arr.len());
    }
    // det
    let cmp_buf = crate::feedback::CmpBuf {
        id: 0,
        offset: 0,
        buf: vec![1, 2, 3, 4],
        det: true,
    };
    println!("state: {:?}", state.mutate.borrow_mut());
    state.mutate.borrow_mut().deterministic = true;
    state.mutate.borrow_mut().det_iter = 0;
    state.mutate.borrow_mut().affect_cmp_buf(cmp_buf);
    let _op = arr.det_mutate(&mut state).unwrap();
    println!("arr: {arr:?}");
    assert!(arr.starts_with(&[1, 2, 3, 4, 0]));
}

#[test]
fn test_vec_gen_mutate() {
    use crate::test;
    // primitive type: u8
    {
        // generate
        let mut state = ObjectState::root("test", "Vec<u8>");
        let mut list = <Vec<u8>>::generate_new(&mut state).unwrap();
        println!("v: {list:?}");
        assert_eq!(state.children.len(), list.len());
        assert_eq!(*list.last().unwrap(), 0);
        // mutate
        for _ in 0..200 {
            let op = list.mutate(&mut state).unwrap();
            println!("op : {op:?}");
            assert!(!op.is_nop());
            assert_seq_state(&state, list.len());
            assert_eq!(*list.last().unwrap(), 0);
            // assert!(state.is_deterministic());
        }
        for _ in 0..200 {
            let _ = list.det_mutate(&mut state).unwrap();
            assert_seq_state(&state, list.len());
            assert_eq!(*list.last().unwrap(), 0);
        }
        // det
        let cmp_buf = crate::feedback::CmpBuf {
            id: 0,
            offset: 0,
            buf: vec![1, 2, 3, 4],
            det: true,
        };
        println!("mutate state: {:?}", state.mutate.borrow_mut());
        state.mutate.borrow_mut().deterministic = true;
        state.done_deterministic();
        state.mutate.borrow_mut().deterministic = true;
        state.mutate.borrow_mut().det_iter = 0;
        state.mutate.borrow_mut().affect_cmp_buf(cmp_buf);
        let op = list.det_mutate(&mut state).unwrap();
        println!("op : {op:?}");
        println!("list: {list:?}");
        assert!(list.starts_with(&[1, 2, 3, 4]));
    }
    // custom type
    {
        let mut state = ObjectState::root("test", "Vec<TestType>");
        let mut list = <Vec<test::TestType>>::generate_new(&mut state).unwrap();
        println!("v: {list:?}");
        assert_eq!(state.children.len(), list.len());
        // mutate
        for _ in 0..200 {
            let op = list.mutate(&mut state).unwrap();
            println!("op : {op:?}");
            // assert!(!op.is_nop());
            assert_seq_state(&state, list.len());
        }
    }
}

#[test]
fn test_vec_pad() -> eyre::Result<()> {
    // generate
    let mut state = ObjectState::root("test", "Vec<u8>");
    let list = <Vec<u8>>::generate_new(&mut state).unwrap();
    assert_eq!(state.children.len(), list.len());
    assert_eq!(*list.last().unwrap(), 0);
    println!("test vec pad");

    for _ in 0..500 {
        let mut tmp = list.clone();
        let mut tmp_state = state.clone_without_mutate_info(None);
        let base = list.len();
        let len = rng::gen_range(base..=4096);
        let rng_state = rng::save_rng_state();
        println!("pad len: {len}");
        tmp.mutate_by_op(
            &mut tmp_state,
            &[],
            &MutateOperation::VecPad {
                len,
                zero: rng::coin(),
                rng_state,
            },
        )?;
        assert_eq!(tmp.len(), len);
        assert!(tmp.starts_with(&list.as_slice()[..list.len() - 1]));
    }

    Ok(())
}

#[test]
fn test_resize() -> eyre::Result<()> {
    let mut state = ObjectState::root("test", "Vec<u8>");
    let mut list = <Vec<u8>>::generate_new(&mut state).unwrap();
    for _ in 0..2000 {
        let resize_op = resize_vec(&mut list, &mut state)?;
        println!("resize op: {:?}", resize_op);
        assert_eq!(state.children.len(), list.len());
    }
    Ok(())
}
