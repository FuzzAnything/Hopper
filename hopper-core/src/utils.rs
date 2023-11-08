//! Common functions.

use findshlibs::{SharedLibrary, TargetSharedLibrary};
use once_cell::sync::OnceCell;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::{path::Path, time};

use crate::{global_gadgets, Deserialize, Deserializer, FuzzProgram, Serialize};

#[macro_export]
macro_rules! log_trace { ($($arg:expr),*) => { $crate::log!(trace, $($arg),*) }; }
#[macro_export]
macro_rules! log_debug { ($($arg:expr),*) => { $crate::log!(debug, $($arg),*) }; }
#[macro_export]
macro_rules! log_info { ($($arg:expr),*) => { $crate::log!(info, $($arg),*) }; }
#[macro_export]
macro_rules! log_warn { ($($arg:expr),*) => { $crate::log!(warn, $($arg),*) }; }
#[macro_export]
macro_rules! log_error { ($($arg:expr),*) => { $crate::log!(error, $($arg),*) }; }

#[cfg(not(test))]
#[macro_export]
macro_rules! log {
    (trace, $($arg:expr),*) => { log::trace!($($arg),*) };
    (debug, $($arg:expr),*) => { log::debug!($($arg),*) };
    (info, $($arg:expr),*) => { log::info!($($arg),*) };
    (warn, $($arg:expr),*) => { log::warn!($($arg),*) };
    (error, $($arg:expr),*) => { log::error!($($arg),*) };
}

#[cfg(not(test))]
pub static mut LOG_COND: bool = true;

#[cfg(not(test))]
#[macro_export]
macro_rules! log_c {
    (trace, $($arg:expr),*) => { if unsafe { $crate::utils::LOG_COND } { log::trace!($($arg),*) } else { println!($($arg),*) } };
    (debug, $($arg:expr),*) => { if unsafe { $crate::utils::LOG_COND } { log::debug!($($arg),*) } else { println!($($arg),*) } };
    (info, $($arg:expr),*) => { if unsafe { $crate::utils::LOG_COND } { log::info!($($arg),*) } else { println!($($arg),*) } };
    (warn, $($arg:expr),*) => { if unsafe { $crate::utils::LOG_COND } { log::warn!($($arg),*) } else { println!($($arg),*) } };
    (error, $($arg:expr),*) => { if unsafe { $crate::utils::LOG_COND } { log::error!($($arg),*) } else { println!($($arg),*) } };
}

#[cfg(test)]
#[macro_export]
macro_rules! log {
    (trace, $($arg:expr),*) => { println!($($arg),*) };
    (debug, $($arg:expr),*) => { println!($($arg),*) };
    (info, $($arg:expr),*) => { println!($($arg),*) };
    (warn, $($arg:expr),*) => { println!($($arg),*) };
    (error, $($arg:expr),*) => { println!($($arg),*) };
}

#[cfg(test)]
#[macro_export]
macro_rules! log_c {
    (trace, $($arg:expr),*) => { println!($($arg),*) };
    (debug, $($arg:expr),*) => { println!($($arg),*) };
    (info, $($arg:expr),*) => { println!($($arg),*) };
    (warn, $($arg:expr),*) => { println!($($arg),*) };
    (error, $($arg:expr),*) => { println!($($arg),*) };
}

#[inline]
pub fn format_time(secs: u64) -> String {
    let mut s = secs;
    let mut m = s / 60;
    let h = m / 60;
    s %= 60;
    m %= 60;
    format!("[{h:02}:{m:02}:{s:02}]")
}

#[inline]
pub fn format_count(c: usize) -> String {
    if c > 1000000000 {
        let f = c / 10000000;
        format!("{:.2}b", f as f32 / 100.0)
    } else if c > 1000000 {
        let f = c / 10000;
        format!("{:.2}m", f as f32 / 100.0)
    } else if c > 10000 {
        let f = c / 10;
        format!("{:.2}k", f as f32 / 100.0)
    } else {
        format!("{c}")
    }
}

#[inline]
pub fn calculate_speed(c: usize, d: time::Duration) -> f64 {
    let ts = d.as_secs() as f64;
    if ts > 0.0 {
        c as f64 / ts
    } else {
        0.0
    }
}

#[inline]
// Index or length numbers include values whose types are: u16/i16/u32/i32/u64/i64/usize/isize
pub fn is_index_or_length_number(ty: &str) -> bool {
    ty == "u16"
        || ty == "i16"
        || ty == "u32"
        || ty == "i32"
        || ty == "u64"
        || ty == "i64"
        || ty == "usize"
        || ty == "isize"
}

#[inline]
pub fn is_primitive_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "()" | "u8"
            | "i8"
            | "u16"
            | "i16"
            | "u32"
            | "i32"
            | "u64"
            | "i64"
            | "f32"
            | "f64"
            | "char"
            | "bool"
            | "RetVoid"
    )
}

#[inline]
pub fn is_custom_type(type_name: &str) -> bool {
    if cfg!(test) {
        type_name.starts_with("hopper::test")
    } else {
        type_name.starts_with("hopper_harness")
    }
}

#[inline]
pub fn is_option_type(type_name: &str) -> bool {
    type_name.starts_with("core::option")
}

#[inline]
pub fn is_pointer_type(type_name: &str) -> bool {
    is_mut_pointer_type(type_name) || is_const_pointer_type(type_name)
}

#[inline]
pub fn is_mut_pointer_type(type_name: &str) -> bool {
    type_name.starts_with("hopper::runtime::FuzzMutPointer")
}
#[inline]
pub fn is_const_pointer_type(type_name: &str) -> bool {
    type_name.starts_with("hopper::runtime::FuzzConstPointer")
}

#[inline]
pub fn is_variadic_function(type_names: &[&str]) -> bool {
    if let Some(p) = type_names.last() {
        return *p == "...";
    }
    false
}

#[inline]
pub fn is_vec_type(type_name: &str) -> bool {
    type_name.starts_with("alloc::vec::Vec")
}

#[inline]
pub fn is_byte(type_name: &str) -> bool {
    type_name == "i8" || type_name == "u8" || type_name == "char"
}

#[inline]
pub fn is_c_str_type(type_name: &str) -> (bool, bool) {
    let mut is_buf = false;
    let mut is_mut = false;
    if type_name == "hopper::runtime::FuzzMutPointer<i8>" {
        is_buf = true;
        is_mut = true;
    } else if type_name == "hopper::runtime::FuzzConstPointer<i8>" {
        is_buf = true;
    }
    (is_buf, is_mut)
}

#[inline]
pub fn is_buffer_pointer(ty: &str) -> bool {
    if let Some(inner) = get_pointer_inner(ty) {
        return is_byte(inner);
    }
    false
}

#[inline]
pub fn is_void_type(type_name: &str) -> bool {
    type_name == "hopper::runtime::FuzzVoid"
}

#[inline]
pub fn is_void_pointer(type_name: &str) -> bool {
    if let Some(inner) = get_pointer_inner(type_name) {
        return is_void_type(inner);
    }
    false
}

#[inline]
pub fn is_opaque_type(type_name: &str) -> bool {
    crate::global_gadgets::get_instance()
        .opaque_types
        .contains(type_name)
}

#[inline]
pub fn get_pointer_inner(type_name: &str) -> Option<&'_ str> {
    if let Some(t) = type_name.strip_prefix("hopper::runtime::") {
        if let Some(t) = t.strip_prefix("FuzzConstPointer<") {
            return t.strip_suffix('>');
        }
        if let Some(t) = t.strip_prefix("FuzzMutPointer<") {
            return t.strip_suffix('>');
        }
    }
    None
}

#[inline]
pub fn is_opaque_pointer(type_name: &str) -> bool {
    if let Some(inner) = get_pointer_inner(type_name) {
        return is_opaque_type(inner);
    }
    // we may put alias name for pointers in opaque_types in gadgets
    is_opaque_type(type_name)
}

#[inline]
pub fn get_vec_inner(type_name: &str) -> Option<&'_ str> {
    if let Some(t) = type_name.strip_prefix("alloc::vec::Vec<") {
        return t.strip_suffix('>');
    }
    None
}

#[inline]
pub fn is_opaque_vec(type_name: &str) -> bool {
    if let Some(inner) = get_vec_inner(type_name) {
        return is_opaque_type(inner);
    }
    false
}

#[inline]
pub fn const_pointer_type(type_name: &str) -> String {
    format!("hopper::runtime::FuzzConstPointer<{type_name}>")
}

#[inline]
pub fn mut_pointer_type(type_name: &str) -> String {
    format!("hopper::runtime::FuzzMutPointer<{type_name}>")
}

#[inline]
pub fn pointer_type(type_name: &str, is_mut: bool) -> String {
    if is_mut {
        mut_pointer_type(type_name)
    } else {
        const_pointer_type(type_name)
    }
}

#[inline]
pub fn is_same_type(l_ty: &str, r_ty: &str) -> bool {
    l_ty == r_ty
        || get_pointer_inner(l_ty)
            .zip(get_pointer_inner(r_ty))
            .map_or(false, |(l_inner, r_inner)| l_inner == r_inner)
}

#[inline]
pub fn get_static_ty(type_name: &str) -> &'static str {
    let gadgets = global_gadgets::get_mut_instance();
    if gadgets.ty_strings.is_empty() {
        gadgets.init_ty_strings();
    }

    if !gadgets.ty_strings.contains(type_name) {
        gadgets.ty_strings.insert(type_name.to_string());
    }
    gadgets.ty_strings.get(type_name).unwrap()
}

#[inline]
pub fn vec_type(type_name: &str) -> String {
    format!("alloc::vec::Vec<{type_name}>")
}

use std::hash::{Hash, Hasher};

pub fn hash_buf(buf: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    buf.hash(&mut hasher);
    hasher.finish()
}

#[derive(Default)]
pub struct TimeUsage {
    total: u128,
    num: u64,
}

impl TimeUsage {
    pub fn count(&mut self) -> TimeCounter {
        TimeCounter {
            t: time::Instant::now(),
            usage: self,
        }
    }

    pub fn add_time(&mut self, t: &time::Instant) {
        self.total += t.elapsed().as_micros();
        self.num += 1;
    }

    pub fn format(&self) -> String {
        format_time((self.total / 1_000_000) as u64)
    }

    pub fn percent(&self, all_secs: u64) -> String {
        let per = if all_secs == 0 {
            0
        } else {
            self.total / 10_000 / all_secs as u128
        };
        format!("{per}%")
    }

    pub fn avg_micro(&self) -> f64 {
        if self.num == 0 {
            0.0
        } else {
            (self.total / self.num as u128) as f64
        }
    }

    pub fn avg_ms(&self) -> String {
        let avg = self.avg_micro() / 1000.0;
        format!("{avg:.2}ms")
    }
}

pub struct TimeCounter<'a> {
    pub t: time::Instant,
    pub usage: &'a mut TimeUsage,
}

impl<'a> Drop for TimeCounter<'a> {
    fn drop(&mut self) {
        self.usage.add_time(&self.t);
    }
}

pub fn is_in_shlib(ptr: *const u8) -> bool {
    static BOUNDARY: OnceCell<(usize, usize)> = OnceCell::new();
    let (start, end) = BOUNDARY.get_or_init(|| {
        let mut path = std::env::current_exe().unwrap();
        path.pop();
        path.pop();
        let dir = path.to_str().unwrap();
        let mut start = 0;
        let mut end = 0;
        TargetSharedLibrary::each(|shlib| {
            let name = shlib.name().to_string_lossy();
            if name.starts_with(dir) && !name.ends_with("hopper-harness") {
                start = shlib.actual_load_addr().into();
                end = start + shlib.len();
            }
        });
        (start, end)
    });
    let ptr = ptr as usize;
    ptr > *start && ptr < *end
}

#[inline]
pub fn is_unwritable(ptr: *const u8) -> bool {
    if let Ok(r) = region::query(ptr) {
        !r.is_writable()
    } else {
        false
    }
}

pub struct FileAppender {
    pub fd: File,
}

impl FileAppender {
    pub fn create<T: AsRef<Path>>(path: T) -> eyre::Result<Self> {
        let fd = File::create(path)?;
        Ok(Self { fd })
    }

    pub fn open<T: AsRef<Path>>(path: T) -> eyre::Result<Self> {
        let fd = std::fs::OpenOptions::new().append(true).open(path)?;
        Ok(Self { fd })
    }

    pub fn append<T: Serialize>(&mut self, item: &T) -> eyre::Result<()> {
        let buf = item.serialize()?;
        self.fd.write_all(buf.as_bytes())?;
        writeln!(self.fd)?;
        Ok(())
    }

    pub fn append_list<T: Serialize>(&mut self, list: &[T]) -> eyre::Result<()> {
        for item in list {
            self.append(item)?;
        }
        Ok(())
    }
}

pub fn read_list_from_file<R: AsRef<Path>, T: Deserialize>(path: R) -> eyre::Result<Vec<T>> {
    let mut list = vec![];
    let p: &Path = path.as_ref();
    if !p.exists() {
        crate::log!(warn, "file {:?} does not exist!", p);
        return Ok(list);
    }
    let file = File::open(p)?;
    let reader = BufReader::new(&file);
    for line in reader.lines() {
        let line = line?;
        let mut de = Deserializer::new(&line, None);
        let item = T::deserialize(&mut de)?;
        list.push(item);
    }
    Ok(list)
}

pub fn read_list_with_program_from_file<R: AsRef<Path>, T: Deserialize>(
    path: R,
    program: &mut FuzzProgram,
) -> eyre::Result<Vec<T>> {
    let mut list = vec![];
    let p: &Path = path.as_ref();
    if !p.exists() {
        crate::log!(warn, "file {:?} does not exist!", p);
        return Ok(list);
    }
    let file = File::open(p)?;
    let reader = BufReader::new(&file);
    for line in reader.lines() {
        if let Err(e) = line {
            crate::log!(warn, "fail to parse review result ({p:?}): {e:?}");
            break;
        }
        let line = line?;
        let mut de = Deserializer::new(&line, Some(program));
        let item = T::deserialize(&mut de)?;
        list.push(item);
    }
    Ok(list)
}
