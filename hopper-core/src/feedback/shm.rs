use crate::error;
use std::{
    self,
    ops::{Deref, DerefMut},
};

/// Shared memory, used for IPC communication between the fuzzer and testing targets.
pub struct SharedMemory<T: Sized> {
    /// SHMID
    pub id: i32,
    /// size of shared memory
    pub size: usize,
    /// content of shared memory
    pub ptr: *mut T,
}

impl<T> SharedMemory<T> {
    /// Create a shared memory at a proper location
    pub fn new() -> eyre::Result<Self> {
        Self::new_at(std::ptr::null())
    }

    /// Create a shared memory at specific location of process memory
    pub fn new_at(ptr_base: *const libc::c_void) -> eyre::Result<Self> {
        let size = std::mem::size_of::<T>();
        let id = unsafe {
            libc::shmget(
                libc::IPC_PRIVATE,
                size,
                libc::IPC_CREAT | libc::IPC_EXCL | 0o600,
            )
        };
        error::check_os_error(id, "shmget fail")?;
        Self::from_id_at(id, ptr_base)
    }

    /// Load shared memory by its SHMID
    pub fn from_id(id: i32) -> eyre::Result<Self> {
        Self::from_id_at(id, std::ptr::null())
    }

    /// Load shared memory by its SHMID at specific location of process memory
    fn from_id_at(id: i32, ptr_base: *const libc::c_void) -> eyre::Result<Self> {
        let size = std::mem::size_of::<T>();
        let ptr = unsafe { libc::shmat(id as libc::c_int, ptr_base, 0) as *mut T };
        error::check_os_error(ptr as i64, "shmat fail")?;
        Ok(SharedMemory::<T> { id, size, ptr })
    }

    /// Clear content at shared memory
    pub fn clear(&mut self) {
        unsafe { libc::memset(self.ptr as *mut libc::c_void, 0, self.size) };
    }

    /// Get unique key for environment
    pub fn get_env_var(&self) -> String {
        self.id.to_string()
    }
}

pub fn setup_shm<T: super::SHMable>() -> eyre::Result<SharedMemory<T>> {
    let id = match std::env::var(T::shmid_env_var()) {
        Ok(s) => Some(s.parse::<i32>()?),
        Err(_) => None,
    };
    let shm = if cfg!(feature = "e9_mode") {
        crate::log!(info, "setup {} shm for e9 runtime...", T::name());
        let ret = unsafe { libc::munmap(T::ptr_base() as *mut libc::c_void, T::buf_size()) };
        crate::error::check_os_error(ret, "munmap fail")?;
        if let Some(id) = id {
            SharedMemory::<T>::from_id_at(id, T::ptr_base())?
        } else {
            SharedMemory::<T>::new_at(T::ptr_base())?
        }
    } else {
        // llvm or cov mode
        if let Some(id) = id {
            SharedMemory::<T>::from_id(id)?
        } else {
            SharedMemory::<T>::new()?
        }
    };
    crate::log!(
        info,
        "setup {} shared memory success ! id: {:?}, shm: {:?}",
        T::name(),
        id,
        shm
    );
    Ok(shm)
}

impl<T> Deref for SharedMemory<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}

impl<T> DerefMut for SharedMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.ptr }
    }
}

impl<T> std::fmt::Debug for SharedMemory<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}, {:#x}, {:p}", self.id, self.size, self.ptr)
    }
}

impl<T> Drop for SharedMemory<T> {
    fn drop(&mut self) {
        let ret = unsafe { libc::shmctl(self.id, libc::IPC_RMID, std::ptr::null_mut()) };
        if let Err(e) = error::check_os_error(ret, "fail to remove shm") {
            crate::log!(error, "{}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u8() {
        let mut one = SharedMemory::<u8>::new().unwrap();
        *one = 1;
        assert_eq!(1, *one);
    }

    #[test]
    fn test_array() {
        let mut arr = SharedMemory::<[u8; 10]>::new().unwrap();
        arr.clear();
        let sl = &mut arr;
        assert_eq!(0, sl[4]);
        sl[4] = 33;
        assert_eq!(33, sl[4]);
    }

    #[test]
    fn test_shm_fail() {
        let arr = SharedMemory::<[u8; 10]>::from_id(88888888);
        println!("arr: {arr:?}");
        assert!(arr.is_err());
        let arr = SharedMemory::<[u8; 10]>::new();
        assert!(arr.is_ok());
        let arr2 = SharedMemory::<[u8; 10]>::from_id(arr.unwrap().id);
        assert!(arr2.is_ok());
    }
}
