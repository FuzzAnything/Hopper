//! Mutate buffer ([u8] or [i8]) without format-aware.
//! use AFL-like mutation

use std::{
    io::{BufRead, Read},
    path::PathBuf,
};

use eyre::{Context, ContextCompat};
use once_cell::sync::OnceCell;

use super::*;
use crate::{fuzz::effective, runtime::*};

static BUF_SEEDS: OnceCell<Vec<(Option<String>, Vec<u8>)>> = OnceCell::new();
static BUF_DICTS: OnceCell<Vec<(Option<String>, Vec<u8>)>> = OnceCell::new();

pub trait BufMutate {
    /// Mutate the buffer without format-aware
    fn mutate_buf(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator>;

    /// Mutate the buffer by specific opeartion
    fn mutate_buf_by_op(
        &mut self,
        state: &mut ObjectState,
        keys: &[FieldKey],
        op: &MutateOperation,
    ) -> eyre::Result<()>;

    /// Splice the buffer with another buffer randomly
    fn splice_buf(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperation>;

    /// Randomly havoc the buffer
    fn havoc_buf(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator>;

    /// Randomly insert tokens from dictionary
    fn insert_dict_token(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperation>;
}

impl<T: ObjFuzzable + ObjGenerate> BufMutate for Vec<T> {
    fn mutate_buf(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        crate::log!(trace, "mutate buf");
        if rng::unlikely() && self.len() > 20 {
            let op = self.splice_buf(state).context("fail to splice buf")?;
            if !op.is_nop() {
                return Ok(state.as_mutate_operator(op));
            }
        }
        if rng::rarely() {
            let op = self.insert_dict_token(state)?;
            if !op.is_nop() {
                return Ok(state.as_mutate_operator(op));
            }
        }
        self.havoc_buf(state).context("fail to havoc buf")
    }

    fn mutate_buf_by_op(
        &mut self,
        state: &mut ObjectState,
        keys: &[FieldKey],
        op: &MutateOperation,
    ) -> eyre::Result<()> {
        match op {
            MutateOperation::BufSplice {
                program_id,
                stmt_index,
                split_at,
                range,
            } => {
                let ele_type_name = std::any::type_name::<T>();
                let ident = state.key.as_str()?;
                let key = format!("{ident}_{ele_type_name}");
                let buf1 = self;
                if *split_at >= buf1.len() {
                    return Ok(());
                }
                let found: eyre::Result<bool> = effective::EFFECT.with(|eff| {
                    if let Some(list) = eff.borrow().buf_list.get(&key) {
                        if let Some(seed) = list
                            .iter()
                            .find(|s| s.program_id == *program_id && s.stmt_index == *stmt_index)
                        {
                            if let Some(r) = range {
                                if *split_at >= buf1.len() || r.upper > seed.buf.len() {
                                    return Ok(true);
                                }
                                let chunk = &seed.buf[r.lower..r.upper];
                                super::seq::vec_insert_chunk(
                                    buf1,
                                    state,
                                    *split_at,
                                    chunk,
                                    r.is_insert,
                                )?;
                            } else {
                                if *split_at >= seed.buf.len() {
                                    return Ok(true);
                                }
                                let buf2 = unsafe {
                                    std::slice::from_raw_parts(
                                        seed.buf.as_ptr() as *const T,
                                        seed.buf.len(),
                                    )
                                };
                                splice_buf_at(buf1, buf2, state, *split_at);
                            }
                            return Ok(true);
                        }
                    }
                    Ok(false)
                });
                if found? {
                    return Ok(());
                }

                // If our cached buf list does not contain such buffer,
                // try to read it from disk.
                let p = crate::depot::read_input_in_queue(*program_id)?;
                let buf2_value = p.stmts[*stmt_index]
                    .stmt
                    .get_value()
                    .context("buf has value")?;
                let buf2 = buf2_value
                    .downcast_ref::<Vec<T>>()
                    .context("downcast buf")?;
                if *split_at >= buf2.len() {
                    return Ok(());
                }
                splice_buf_at(buf1, buf2, state, *split_at);
            }
            MutateOperation::BufHavoc {
                use_bytes,
                swap,
                op,
            } => {
                let buf = self;
                let fields = op.key.fields.as_slice();
                eyre::ensure!(!fields.is_empty(), "key should at least 2 fields");
                let offset = fields.last().unwrap().as_usize()?;
                if offset >= buf.len() {
                    return Ok(());
                }
                let val = &mut buf[offset];
                let op = &op.op;
                let sub_state = state.get_child_mut(offset)?;
                macro_rules! mutate_num_by_op {
                    ($ty:ident) => {{
                        let ptr = val as *mut T as *mut $ty;
                        if !swap && ptr.align_offset(std::mem::align_of::<$ty>()) == 0 {
                            let num = unsafe { ptr.as_mut().unwrap() };
                            num.mutate_by_op(sub_state, &[], op)?;
                        } else {
                            let mut num = unsafe { ptr.read_unaligned() };
                            if !swap {
                                num.mutate_by_op(sub_state, &[], op)?;
                            } else {
                                let mut swap_num = num.swap_bytes();
                                swap_num.mutate_by_op(sub_state, &[], op)?;
                                num = swap_num.swap_bytes();
                            }
                            unsafe { ptr.write_unaligned(num) };
                        }
                    }};
                }
                match *use_bytes {
                    1 => {
                        val.mutate_by_op(sub_state, &[], op)?;
                    }
                    2 => {
                        mutate_num_by_op!(u16);
                    }
                    4 => {
                        mutate_num_by_op!(u32);
                    }
                    8 => {
                        mutate_num_by_op!(u64);
                    }
                    _ => {
                        unreachable!();
                    }
                }
            }
            MutateOperation::UseDict {
                offset,
                dict,
                is_insert,
            } => {
                super::seq::vec_insert_chunk(self, state, *offset, dict.as_slice(), *is_insert)?;
            }
            _ => {
                self.as_mut_slice().mutate_by_op(state, keys, op)?;
            }
        }
        Ok(())
    }

    fn splice_buf(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperation> {
        let ele_type_name = std::any::type_name::<T>();
        let ident = state.key.as_str()?;
        let key = format!("{ident}_{ele_type_name}");
        let buf1 = unsafe { std::slice::from_raw_parts(self.as_ptr() as *const u8, self.len()) };
        // Get current buffer's hash
        let hash = crate::utils::hash_buf(buf1);
        // Pick a random entry. Don't splice with yourself.
        effective::EFFECT.with(|eff| {
            if let Some(list) = eff.borrow().buf_list.get(&key) {
                let iter = list.iter().filter(|s| s.hash != hash);
                if let Some(seed) = rng::choose_iter(iter) {
                    crate::log!(
                        trace,
                        "splice with program {} index: {}",
                        seed.program_id,
                        seed.stmt_index
                    );
                    let buf2 = &seed.buf[..];
                    // crossover insert/overwrite
                    if rng::coin() && buf1.len() > 2 && buf2.len() > 4 {
                        let lower = rng::gen_range(0..buf2.len() - 4);
                        let upper = rng::gen_range(lower + 4..buf2.len());
                        let chunk = &buf2[lower..upper];
                        eyre::ensure!(chunk.len() >= 4, "chunk has at least 4 bytes");
                        let split_at = rng::gen_range(1..buf1.len() - 1);
                        let is_insert = rng::coin();
                        super::seq::vec_insert_chunk(self, state, split_at, chunk, is_insert)?;
                        return Ok(MutateOperation::BufSplice {
                            program_id: seed.program_id,
                            stmt_index: seed.stmt_index,
                            split_at,
                            range: Some(crate::SpliceRange {
                                lower,
                                upper,
                                is_insert,
                            }),
                        });
                    }

                    // splice at specific position
                    // we cast them to u8 since T havn't Eq trait
                    if let Some(split_at) = find_splice_pos(buf1, buf2) {
                        let buf1 = self;
                        let buf2 = unsafe {
                            std::slice::from_raw_parts(
                                seed.buf.as_ptr() as *const T,
                                seed.buf.len(),
                            )
                        };
                        splice_buf_at(buf1, buf2, state, split_at);
                        return Ok(MutateOperation::BufSplice {
                            program_id: seed.program_id,
                            stmt_index: seed.stmt_index,
                            split_at,
                            range: None,
                        });
                    }
                }
            }
            Ok(MutateOperation::Nop)
        })
    }

    /// Try afl-like havoc mutation for bytes
    fn havoc_buf(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        let buf_len = self.len();
        let use_bytes = use_bytes(buf_len);
        let swap = rng::unlikely();
        let mut offset = weight::choose_weighted_by_state(state).unwrap_or(buf_len);
        if offset > buf_len - use_bytes {
            offset = rng::gen_range(0..buf_len - use_bytes + 1);
        }
        let buf = self;
        let val = &mut buf[offset];
        let sub_state = state.get_child_mut(offset)?;
        // FIXME:
        macro_rules! mutate_num {
            ($ty:ident) => {{
                let ptr = val as *mut T as *mut $ty;
                let op_ret;
                if !swap && ptr.align_offset(std::mem::align_of::<$ty>()) == 0 {
                    let num = unsafe { ptr.as_mut().unwrap() };
                    op_ret = num.mutate(sub_state)?;
                } else {
                    // not align
                    let mut num = unsafe { ptr.read_unaligned() };
                    if !swap {
                        op_ret = num.mutate(sub_state)?;
                    } else {
                        let mut swap_num = num.swap_bytes();
                        op_ret = swap_num.mutate(sub_state)?;
                        num = swap_num.swap_bytes();
                    }
                    unsafe { ptr.write_unaligned(num) };
                }
                op_ret
            }};
        }
        let op = match use_bytes {
            1 => val.mutate(sub_state)?,
            2 => mutate_num!(u16),
            4 => mutate_num!(u32),
            8 => mutate_num!(u64),
            _ => {
                unreachable!();
            }
        };
        let op = MutateOperation::BufHavoc {
            use_bytes,
            swap,
            op: Box::new(op),
        };
        Ok(state.as_mutate_operator(op))
    }

    /// Try to insert or overwrite values in dictionary
    fn insert_dict_token(&mut self, state: &mut ObjectState) -> eyre::Result<MutateOperation> {
        let ident = state.key.as_str().unwrap();
        let dicts = get_buf_dict_tokens(ident);
        if let Some(value) = rng::choose_slice(dicts.as_slice()) {
            let buf_len = self.len();
            let offset = rng::gen_range(0..buf_len);
            // insert or replace
            let is_insert = rng::coin();
            super::seq::vec_insert_chunk(self, state, offset, value, is_insert)?;
            return Ok(MutateOperation::UseDict {
                offset,
                dict: value.to_vec(),
                is_insert,
            });
        }
        Ok(MutateOperation::Nop)
    }
}

/// Find a suitable splicing location, somewhere between the first and
/// the last differing byte.
fn find_splice_pos(buf1: &[u8], buf2: &[u8]) -> Option<usize> {
    let (f_loc, l_loc) = locate_diffs(buf1, buf2);
    if f_loc.is_none() || l_loc.is_none() {
        return None;
    }
    let f_loc = f_loc.unwrap();
    let l_loc = l_loc.unwrap();
    //  Bail out if the difference is just a single byte or so.
    // f_loc == 0 ||
    if l_loc < 2 || f_loc == l_loc {
        return None;
    }
    let split_at = rng::gen_range(f_loc..l_loc);
    Some(split_at)
}

/// Returns first and last differing offset.
/// We use this to find reasonable locations for splicing two buffers
fn locate_diffs(buf1: &[u8], buf2: &[u8]) -> (Option<usize>, Option<usize>) {
    let len = std::cmp::min(buf1.len(), buf2.len());
    if len < 2 {
        return (None, None);
    }
    let mut first_loc = None;
    let mut last_loc = None;
    for i in 0..len {
        if buf1[i] != buf2[i] {
            if first_loc.is_none() {
                first_loc = Some(i);
            }
            last_loc = Some(i);
        }
    }

    (first_loc, last_loc)
}

fn splice_buf_at<T: ObjFuzzable + ObjGenerate>(
    buf1: &mut Vec<T>,
    buf2: &[T],
    state: &mut ObjectState,
    split_at: usize,
) {
    let mut new_buf = [&buf1[..split_at], &buf2[split_at..]].concat();
    std::mem::swap(buf1, &mut new_buf);
    // resize state
    state.children.truncate(split_at);
    for _ in split_at..buf1.len() {
        let idx = state.children.len();
        let _ = state.add_child(idx, std::any::type_name::<T>());
    }
}

/// Choose how many bytes we used
fn use_bytes(buf_len: usize) -> usize {
    let max: usize = if buf_len >= 8 {
        4
    } else if buf_len >= 4 {
        3
    } else if buf_len >= 2 {
        2
    } else if buf_len >= 1 {
        1
    } else {
        unreachable!()
    };
    1 << rng::gen_range(0..max)
}

/// Get seeds from environment(directory) for byte arguments.
/// if there are sub-directory starts with `@` (e.g @png), then it is for the arguments whose name is png.
pub fn get_buf_seeds(index: usize, ident: &str) -> Option<&'static [u8]> {
    let list = BUF_SEEDS.get_or_init(|| {
        let path = if let Ok(path) = std::env::var("HOPPER_SEED_DIR") {
            crate::log!(info, "load seed path: {}", path);
            PathBuf::from(path)
        } else {
            crate::config::output_file_path("seeds")
        };
        let list = read_buf_seeds_from_dir(&path, None);
        crate::log!(info, "add {} seeds for buf", list.len());
        list
    });
    list.iter()
        .filter_map(|(i, t)| {
            if let Some(name) = i {
                if name != ident {
                    return None;
                }
            }
            Some(t.as_slice())
        })
        .nth(index)
}

fn read_buf_seeds_from_dir(
    path: &std::path::Path,
    ident: Option<String>,
) -> Vec<(Option<String>, Vec<u8>)> {
    let mut list = vec![];
    if !path.is_dir() {
        return list;
    }
    for entry in path.read_dir().unwrap() {
        let file = entry.unwrap().path();
        if file.is_dir() {
            let f_name = file.to_str().unwrap();
            // if directory starts with '@', only for specific ident
            if let Some(rest) = f_name.strip_prefix('@') {
                list.extend(read_buf_seeds_from_dir(&file, Some(rest.to_string())));
            } else {
                list.extend(read_buf_seeds_from_dir(&file, ident.clone()));
            }
        }
        if !file.is_file() {
            continue;
        }
        if file.metadata().unwrap().len() > 10000 {
            continue;
        }
        let mut f = std::fs::File::open(file).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        list.push((ident.clone(), buf));
    }
    list
}

/// Parse dictionarys, e.g:
/// # IVF Signature + version (bytes 0-5)
/// kw1="DKIF\x00\x00"
/// section_2101="!\x01\x12"
pub fn get_buf_dict_tokens(ident: &str) -> Vec<&'static [u8]> {
    let dicts = BUF_DICTS.get_or_init(|| {
        let default_dict = crate::config::output_file_path("misc/dict");
        let path = if let Ok(path) = std::env::var("HOPPER_DICT") {
            crate::log!(info, "load dict path: {}", path);
            std::fs::copy(&path, default_dict)
                .expect("fail to open dict file! please check the file is exist or not");
            PathBuf::from(path)
        } else {
            default_dict
        };
        if path.is_file() {
            let mut f = std::fs::File::open(path).unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            parse_dictionary(&buf)
        } else {
            vec![]
        }
    });
    dicts
        .iter()
        .filter_map(|(i, t)| {
            if let Some(name) = i {
                if name != ident {
                    return None;
                }
            }
            Some(t.as_slice())
        })
        .collect()
}

fn parse_dictionary(buf: &[u8]) -> Vec<(Option<String>, Vec<u8>)> {
    let mut list = vec![];
    for line in buf.lines() {
        let line = line.unwrap();
        let mut l = line.trim();
        let mut ident = None;
        if l.is_empty() || l.starts_with('#') || l.starts_with("//") {
            continue;
        }
        if !l.starts_with('"') {
            if let Some(pos) = l.find('"') {
                let prefix = &l[..pos];
                if let Some(eq_pos) = prefix.find('=') {
                    // if kw starts with '@', only for specific ident
                    let kw = l[..eq_pos].trim();
                    if let Some(rest) = kw.strip_prefix('@') {
                        ident = Some(rest.to_string());
                    }
                }
                l = &l[pos..];
            } else {
                continue;
            }
        }
        if l.is_empty() {
            continue;
        }
        l = &l[1..];
        if let Some(pos) = l.find('"') {
            l = &l[..pos];
        } else {
            continue;
        }
        let mut dict_value = vec![];
        let mut citer = l.chars();
        while let Some(c) = citer.next() {
            let c = c as u8;
            if !(32..128).contains(&c) {
                continue;
            }
            if c == b'\\' && citer.next() == Some('x') {
                let first = citer.next().context("has first").unwrap();
                let second = citer.next().context("has second").unwrap();
                if first.is_ascii_hexdigit() && second.is_ascii_hexdigit() {
                    let v = (first.to_digit(16).unwrap() << 4) | second.to_digit(16).unwrap();
                    dict_value.push(v as u8);
                }
                continue;
            }
            dict_value.push(c);
        }
        list.push((ident, dict_value));
    }
    list
}

#[test]
fn test_buf_mutate() {
    let mut buf = vec![0_u8; 10];
    let ptr = &mut buf[1] as *mut u8 as *mut u32;
    unsafe { ptr.write_unaligned(0x1234) };
    println!("{buf:?}");
    assert_eq!(buf[1], 0x34);
    assert_eq!(buf[2], 0x12);
    let ptr = &mut buf[5] as *mut u8 as *mut u32;
    let val = 0x1234_u32.swap_bytes();
    unsafe { ptr.write_unaligned(val) };
    println!("{buf:?}");
    assert_eq!(buf[7], 0x12);
    assert_eq!(buf[8], 0x34);
}

#[test]
fn test_buf() {
    use crate::fuzz::effective::EffectiveBuf;
    {
        let mut seeds = vec![];
        for i in 0..10 {
            let buf: Vec<u8> = (0..100).map(|_| rng::gen::<u8>()).collect();
            seeds.push(EffectiveBuf {
                program_id: i,
                stmt_index: i,
                buf,
                hash: i as u64,
            });
        }
        effective::EFFECT.with(|eff| {
            eff.borrow_mut()
                .buf_list
                .insert("test_i8".to_string(), seeds);
        });
    }
    let mut buf = vec![0_i8; 64];
    let mut state = ObjectState::root("test", std::any::type_name::<i8>());
    for _ in 0..buf.len() {
        let idx = state.children.len();
        let _ = state.add_child(idx, std::any::type_name::<i8>());
    }
    for _ in 0..1000 {
        println!("----------------------");
        let mut buf2 = buf.clone();
        let mut state2 = state.clone_without_mutate_info(None);
        let op = buf.mutate_buf(&mut state).unwrap();
        println!("op: {}", op.serialize().unwrap());
        println!("buf_len: {} / {}", buf.len(), state.children.len());
        assert!(!op.is_nop());
        buf2.mutate_buf_by_op(&mut state2, op.key.fields.as_slice(), &op.op)
            .unwrap();
        println!("buf: {buf:?}");
        println!("buf2: {buf2:?}");
        assert_eq!(buf, buf2);
    }

    for _ in 0..100 {
        let op = buf.splice_buf(&mut state).unwrap();
        println!("op: {op:?}");
    }
}

#[test]
fn test_parse_dict() {
    let buf = r#"kw1="DKIF\x00\x00"
    section_2101="!\x01\x12"
    @test="123""#;
    let ret = BUF_DICTS.get_or_init(|| parse_dictionary(buf.as_bytes()));
    if ret.is_empty() {
        return;
    }
    let list = get_buf_dict_tokens("abc");
    assert_eq!(list.len(), 2);
    let list = get_buf_dict_tokens("test");
    assert_eq!(list.len(), 3);
}
