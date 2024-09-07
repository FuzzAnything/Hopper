use crate::{config, BucketType, BRANCHES_SIZE};

use super::SHMable;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[repr(transparent)]
pub struct Path {
    pub buf: [u8; BRANCHES_SIZE],
}

impl SHMable for Path {
    fn name() -> &'static str {
        "trace"
    }
    fn shmid_env_var() -> &'static str {
        config::PATH_SHMID_VAR
    }
    fn ptr_base() -> *const libc::c_void {
        config::SHM_PATH_BASE as *const libc::c_void
    }
    fn buf_size() -> usize {
        config::BRANCHES_SIZE
    }
    #[cfg(feature = "llvm_mode")]
    fn post_hander(ptr: *const u8) {
        unsafe {
            __hopper_area_ptr = ptr;
        };
        crate::log!(
            info,
            "update {} shm pointer in llvm runtime !",
            Self::name()
        );
    }
}

#[cfg(feature = "llvm_mode")]
static mut __HOPPER_AREA_INITIAL: [u8; BRANCHES_SIZE] = [255; BRANCHES_SIZE];

#[cfg(feature = "llvm_mode")]
#[no_mangle]
pub static mut __hopper_area_ptr: *const u8 = unsafe { &__HOPPER_AREA_INITIAL[0] as *const u8 };

impl Path {
    pub fn get_list(&self) -> Vec<(usize, BucketType)> {
        let mut path = Vec::<(usize, BucketType)>::new();
        let flat_buf: &BranchFlatBuf = unsafe { std::mem::transmute(&self.buf) };
        for (i, &v) in flat_buf.iter().enumerate() {
            if v > 0 {
                cold();
                let base = i * ENTRY_SIZE;
                for j in 0..ENTRY_SIZE {
                    let idx = base + j;
                    let new_val = self.buf[idx];
                    if new_val > 0 {
                        // crate::log!(trace, "id: {}, val: {}", idx, new_val);
                        path.push((idx, COUNT_LOOKUP[new_val as usize]));
                    }
                }
            }
        }
        path
    }

    pub fn contain_any(&self, edges: &[(usize, BucketType)]) -> bool {
        edges.iter().any(|(idx, _k)| self.buf[*idx] > 0)
    }

    pub fn is_inclued_by(&self, path: &[(usize, BucketType)]) -> bool {
        let crash_path = self.get_list();
        is_sub_set(path, &crash_path)
    }

    pub fn hash_trace(&self) -> u64 {
        let list = self.get_list();
        let mut hasher = DefaultHasher::new();
        list.hash(&mut hasher);
        hasher.finish()
    }
}

fn is_sub_set(path: &[(usize, BucketType)], sub: &[(usize, BucketType)]) -> bool {
    let mut i = 0;
    let mut j = 0;
    let path_len = path.len();
    let sub_len = sub.len();
    while i < sub_len {
        while j < path_len {
            if sub[i].0 == path[j].0 {
                i += 1;
                j += 1;
                break;
            }
            j += 1;
        }
        if j == path_len {
            break;
        }
    }
    i == sub_len
}

/// `cold` is used to mark sth is unlikely to be invoked
#[inline]
#[cold]
fn cold() {}

#[cfg(target_pointer_width = "32")]
type BranchEntry = u32;
#[cfg(target_pointer_width = "64")]
type BranchEntry = u64;
#[cfg(target_pointer_width = "32")]
const ENTRY_SIZE: usize = 4;
#[cfg(target_pointer_width = "64")]
const ENTRY_SIZE: usize = 8;
type BranchFlatBuf = [BranchEntry; config::BRANCHES_SIZE / ENTRY_SIZE];

// Map of bit bucket (8bit)
// [1], [2], [3], [4, 7], [8, 15], [16, 31], [32, 127], [128, infinity]
#[cfg(not(feature = "fat_bucket"))]
static COUNT_LOOKUP: [u8; 256] = [
    0, 1, 2, 4, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
];

// Map of bit bucket (16bit)
// [1], [2], [3], [4], [5], [6], [7], [8], [9], [10], [11], [12],
// [13, 15], [16, 31], [32, 127], [128, infinity]
#[cfg(feature = "fat_bucket")]
static COUNT_LOOKUP: [u16; 256] = [
    0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2056, 4096, 4096, 4096, 8192, 8192, 8192, 8192,
    8192, 8192, 8192, 8192, 8192, 8192, 8192, 8192, 8192, 8192, 8192, 8192, 16384, 16384, 16384,
    16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384,
    16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384,
    16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384,
    16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384,
    16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384,
    16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384,
    16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384,
    16384, 16384, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
];

#[test]
fn test_include() {
    let a = [(1, 1), (2, 1)];
    let b = [(1, 1), (2, 1), (3, 1)];
    assert!(is_sub_set(&b, &a));

    let a = [(1, 1), (2, 1), (4, 1)];
    let b = [(1, 1), (2, 1), (3, 1)];
    assert!(!is_sub_set(&b, &a));
}
