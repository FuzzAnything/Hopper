//! Hooks for llvm mode
//! TODO: indirect invoking

use libc::{c_char, c_int, c_void, mode_t, off_t, size_t, ssize_t, FILE};

use super::get_instr_list_mut;
use crate::{CmpType, MemType};

pub fn add_hooks() -> eyre::Result<()> {
    let map: &[(&str, *const c_void)] = &[
        // compare related
        ("strcmp", __hopper_strcmp as _),
        ("strcoll", __hopper_strcoll as _),
        ("strncmp", __hopper_strncmp as _),
        ("memcmp", __hopper_memcmp as _),
        // memory related
        ("malloc", __hopper_malloc as _),
        ("free", __hopper_free as _),
        ("calloc", __hopper_calloc as _),
        ("realloc", __hopper_realloc as _),
        // file related
        ("fopen", __hopper_fopen as _),
        ("fdopen", __hopper_fdopen as _),
        ("open", unsafe { __hopper_open_fn } as _),
        #[cfg(target_os = "linux")]
        ("open64", unsafe { __hopper_open64_fn } as _),
        ("creat", __hopper_creat as _),
        #[cfg(target_os = "linux")]
        ("creat64", __hopper_creat64 as _),
        ("close", __hopper_close as _),
        ("lseek", __hopper_lseek as _),
        #[cfg(target_os = "linux")]
        ("lseek64", __hopper_lseek64 as _),
        ("read", __hopper_read as _),
        ("write", __hopper_write as _),
    ];

    let library_env = option_env!("HOPPER_LIBRARY").unwrap_or_default();
    let library_list: Vec<&str> = library_env.split(',').collect();
    crate::log!(info, "add hook for libraries: {library_list:?}");

    for lib in library_list {
        let object = plthook::ObjectFile::open_file(lib)?;
        let symbols: Vec<String> = object.symbols().map(|s| s.name.to_string_lossy().into_owned()).collect();
        for &(name, addr) in map {
            if !symbols.iter().any(|s| *s == name) {
                continue;
            }
            let mut rep = unsafe { object.replace(name, addr)? };
            rep.discard();
        }
    }
    Ok(())
}

// get_return_addrss
//#![feature(link_llvm_intrinsics)]
#[cfg(feature = "unstable")]
extern {
    #[link_name = "llvm.returnaddress"]
    fn return_address(a: i32) -> *const u8;
}

#[cfg(feature = "unstable")]
macro_rules! caller_address {
    () => {
        unsafe { return_address(0) }
    };
}
#[cfg(not(feature = "unstable"))]
macro_rules! caller_address {
    () => {
        0
    };
}

/// Trace cmp instruction in LLVM mode
#[no_mangle]
pub extern "C" fn __hopper_trace_cmp(id: u32, op1: u64, op2: u64, size: u32) {
    let ty = CmpType::Instcmp as u16;
    get_instr_list_mut().add_cmp(id, ty, op1, op2, size);
}

/// Trace swich instruction in LLVM mode
#[no_mangle]
pub unsafe extern "C" fn __hopper_trace_switch(
    id: u32,
    val: u64,
    size: u32,
    args: *const u64,
    num: u64,
) {
    let instr = get_instr_list_mut();
    let sw_args = std::slice::from_raw_parts(args, num as usize);
    // instr.add_cmp(id, op1, op2, size);
    let mut id = id;
    let ty = CmpType::Instcmp as u16;
    for arg in sw_args {
        id = id * 33 + 1;
        instr.add_cmp(id, ty, val, *arg, size);
    }
}

/// Trace cmp function in LLVM mode
#[no_mangle]
pub extern "C" fn __hopper_trace_cmp_fn(id: u32, op1: *const u8, op2: *const u8, size: u32) {
    let ty = if size == 0 {
        CmpType::Strcmp as u16
    } else {
        CmpType::Memcmp as u16
    };
    get_instr_list_mut().add_cmp(id, ty, op1 as u64, op2 as u64, size);
}

fn pack_strcmp_prefix(op1: *const c_char, op2: *const c_char) -> u32 {
    let mut state = [0_u8; 4];
    state[0] = unsafe { *op1.add(0) } as u8;
    state[1] = unsafe { *op1.add(1) } as u8;
    state[2] = unsafe { *op2.add(0) } as u8;
    state[3] = unsafe { *op2.add(1) } as u8;
    u32::from_le_bytes(state)
}

pub unsafe extern "C" fn __hopper_strcmp(cs: *const c_char, ct: *const c_char) -> c_int {
    let id = caller_address!();
    let ty = CmpType::Strcmp as u16;
    let prefix = pack_strcmp_prefix(cs, ct);
    get_instr_list_mut().add_cmp_with_prefix(id, ty, cs as u64, ct as u64, 0, prefix);
    libc::strcmp(cs, ct)
}

pub unsafe extern "C" fn __hopper_strcoll(cs: *const c_char, ct: *const c_char) -> c_int {
    let id = caller_address!();
    let ty = CmpType::Strcmp as u16;
    let prefix = pack_strcmp_prefix(cs, ct);
    get_instr_list_mut().add_cmp_with_prefix(id, ty, cs as u64, ct as u64, 0, prefix);
    libc::strcoll(cs, ct)
}

pub unsafe extern "C" fn __hopper_strncmp(
    cs: *const c_char,
    ct: *const c_char,
    n: size_t,
) -> c_int {
    let id = caller_address!();
    let ty = CmpType::Memcmp as u16;
    let prefix = pack_strcmp_prefix(cs, ct);
    get_instr_list_mut().add_cmp_with_prefix(id, ty, cs as u64, ct as u64, n as u32, prefix);
    libc::strncmp(cs, ct, n)
}

// TODO: C++ string compares?
// _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEPKc
// _ZSteqIcSt11char_traitsIcESaIcEEbRKNSt7__cxx1112basic_stringIT_T0_T1_EEPKS5_

pub unsafe extern "C" fn __hopper_memcmp(cx: *const c_void, ct: *const c_void, n: size_t) -> c_int {
    let id = caller_address!();
    let ty = CmpType::Memcmp as u16;
    let prefix = pack_strcmp_prefix(cx as *const c_char, ct as *const c_char);
    get_instr_list_mut().add_cmp_with_prefix(id, ty, cx as u64, ct as u64, n as u32, prefix);
    libc::memcmp(cx, ct, n)
}

#[no_mangle]
pub unsafe extern "C" fn __hopper_malloc(size: size_t) -> *mut c_void {
    let addr = libc::malloc(size);
    if !addr.is_null() {
        libc::memset(addr, 0xFA, size);
    }
    let id: u32 = 0;
    let ty = MemType::Malloc as u16;
    get_instr_list_mut().add_mem(id, ty, addr as u64, size as u32);
    addr
}

#[no_mangle]
pub unsafe extern "C" fn __hopper_free(p: *mut c_void) {
    let id: u32 = 0;
    let ty = MemType::Free as u16;
    get_instr_list_mut().add_mem(id, ty, p as u64, 0);
    if crate::canary::is_in_canary(p as *mut u8) {
        return;
    }
    libc::free(p)
}

pub unsafe extern "C" fn __hopper_calloc(nobj: size_t, size: size_t) -> *mut c_void {
    let addr = libc::calloc(nobj, size);
    let id: u32 = 0;
    let ty = MemType::Calloc as u16;
    let size = nobj * size;
    get_instr_list_mut().add_mem(id, ty, addr as u64, size as u32);
    addr
}

pub unsafe extern "C" fn __hopper_realloc(p: *mut c_void, size: size_t) -> *mut c_void {
    let id: u32 = 0;
    let addr = unsafe { libc::realloc(p, size) };
    let (ty, addr) = if p.is_null() {
        (MemType::ReallocMalloc, addr)
    } else if addr.is_null() {
        (MemType::ReallocFree, p)
    } else if addr == p {
        (MemType::ReallocResize, p)
    } else {
        // free and malloc
        get_instr_list_mut().add_mem(id, MemType::ReallocFree as u16, p as u64, size as u32);
        (MemType::ReallocMalloc, addr)
    };
    get_instr_list_mut().add_mem(id, ty as u16, addr as u64, size as u32);
    addr
}

fn get_file_name_suffix(filename: *const c_char) -> [u8; 4] {
    let mut len = 0;
    let mut start = 0;
    for i in 0..256_usize {
        let c = unsafe { *filename.add(i) };
        // '/'
        if c == 47 {
            start = i + 1;
        } else if c == 0 {
            len = i;
            break;
        }
    }
    if len > 4 && start < len - 4 {
        start = len - 4;
    }
    let mut suffix = [0; 4];
    for (i, val) in suffix.iter_mut().enumerate() {
        *val = unsafe { *filename.add(start + i) } as u8;
    }
    suffix
}

fn get_file_mode(mode: *const c_char) -> u32 {
    let mut read_mode = 2;
    for i in 0..4 {
        let c = unsafe { *mode.offset(i) };
        if c == 0 {
            break;
        }
        if c == 'r' as i8 || c == '+' as i8 {
            read_mode = 1;
        }
    }
    read_mode
}

pub unsafe extern "C" fn __hopper_fopen(filename: *const c_char, mode: *const c_char) -> *mut FILE {
    let id = caller_address!();
    let ty = MemType::Open as u16;
    let addr = filename as u64;
    let read_mode = get_file_mode(mode);
    let size = read_mode;
    let suffix = get_file_name_suffix(filename);
    get_instr_list_mut().add_mem_with_suffix(id, ty, addr, size, suffix);
    libc::fopen(filename, mode)
}

fn is_reserve_fd(fd: c_int) -> bool {
    (crate::config::RESERVED_FD_MIN..=crate::config::RESERVED_FD_MAX).contains(&fd)
}

pub unsafe extern "C" fn __hopper_fdopen(fd: c_int, mode: *const c_char) -> *mut FILE {
    let id = caller_address!();
    let ty = MemType::Fdopen as u16;
    let read_mode = get_file_mode(mode);
    let size = read_mode;
    let addr = fd as u64;
    super::get_instr_list_mut().add_mem(id, ty, addr, size);
    if fd == 0 || ((fd == 1 || fd == 2) && read_mode == 1) || is_reserve_fd(fd) {
        return std::ptr::null_mut();
    }
    libc::fdopen(fd, mode)
}

/*
pub unsafe extern "C" fn __hopper_open(
    path: *const c_char,
    oflag: c_int,
    ...
) -> c_int {
    0
}

pub unsafe extern "C" fn open64(
    path: *const c_char,
    oflag: c_int
    ...
) -> c_int {

}
*/

// in hook.c
extern "C" {
    static __hopper_open_fn: *const c_void;
    static __hopper_open64_fn: *const c_void;
}

#[no_mangle]
pub extern "C" fn __hopper_open_hook(id: u32, path: *const c_char, flags: c_int) {
    // let id = caller_address!();
    let ty = MemType::Open as u16;
    let addr = path as u64;
    let read_mode = if (flags & 1) > 0 { 2 } else { 1 };
    let size = read_mode;
    let suffix = get_file_name_suffix(path);
    super::get_instr_list_mut().add_mem_with_suffix(id, ty, addr, size, suffix);
}

pub unsafe extern "C" fn __hopper_creat(path: *const c_char, mode: mode_t) -> c_int {
    let id = caller_address!();
    let ty = MemType::Open as u16;
    let addr = path as u64;
    let size = 2;
    let suffix = get_file_name_suffix(path);
    super::get_instr_list_mut().add_mem_with_suffix(id, ty, addr, size, suffix);
    libc::creat(path, mode)
}

#[cfg(target_os = "linux")]
pub unsafe extern "C" fn __hopper_creat64(path: *const c_char, mode: mode_t) -> c_int {
    let id = caller_address!();
    let ty = MemType::Open as u16;
    let addr = path as u64;
    let size = 2;
    let suffix = get_file_name_suffix(path);
    super::get_instr_list_mut().add_mem_with_suffix(id, ty, addr, size, suffix);
    libc::creat64(path, mode)
}

pub unsafe extern "C" fn __hopper_close(fd: c_int) -> c_int {
    let id = caller_address!();
    let ty = MemType::Close as u16;
    let addr = fd as u64;
    let size = 1;
    super::get_instr_list_mut().add_mem(id, ty, addr, size);
    if is_reserve_fd(fd) {
        return 0;
    }
    libc::close(fd)
}

pub unsafe extern "C" fn __hopper_lseek(fd: c_int, offset: off_t, whence: c_int) -> off_t {
    let id = caller_address!();
    let ty = MemType::Lseek as u16;
    let addr = fd as u64;
    let size = 1;
    super::get_instr_list_mut().add_mem(id, ty, addr, size);
    if fd == 0 || is_reserve_fd(fd) {
        return -1;
    }
    libc::lseek(fd, offset, whence)
}

#[cfg(target_os = "linux")]
pub unsafe extern "C" fn __hopper_lseek64(fd: c_int, offset: libc::off64_t, whence: c_int) -> libc::off64_t {
    let id = caller_address!();
    let ty = MemType::Lseek as u16;
    let addr = fd as u64;
    let size = 1;
    super::get_instr_list_mut().add_mem(id, ty, addr, size);
    if fd == 0 || is_reserve_fd(fd) {
        return -1;
    }
    libc::lseek64(fd, offset, whence)
}

pub unsafe extern "C" fn __hopper_read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
    let id = caller_address!();
    let ty = MemType::Read as u16;
    let addr = fd as u64;
    let size = 2;
    super::get_instr_list_mut().add_mem(id, ty, addr, size);
    if fd == 0 || fd == 1 || fd == 2 || is_reserve_fd(fd) {
        return -1;
    }
    libc::read(fd, buf, count)
}

pub unsafe extern "C" fn __hopper_write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
    let id = caller_address!();
    let ty = MemType::Write as u16;
    let addr = fd as u64;
    let size = 1;
    super::get_instr_list_mut().add_mem(id, ty, addr, size);
    if fd == 0 || is_reserve_fd(fd) {
        return -1;
    }
    libc::write(fd, buf, count)
}
