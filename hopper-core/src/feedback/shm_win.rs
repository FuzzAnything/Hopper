use super::SHMable;
use std::ops::{Deref, DerefMut};

/// Shared memory, used for IPC communication between the fuzzer and testing targets.
pub struct SharedMemory<T: Sized> {
    /// SHMID
    pub handle: crate::execute::Handle,
    /// size of shared memory
    pub size: usize,
    /// content of shared memory
    pub ptr: *mut T,
}

impl<T> SharedMemory<T> {
    /// Create a shared memory at a proper location
    #[cfg(test)]
    pub fn new() -> eyre::Result<Self> {
        let ptr_base = crate::execute::NULL;
        let lp_name = "TEST".to_string(); 
        Self::new_at(ptr_base, &lp_name)
    }

    /// Create a shared memory at specific location of process memory
    pub fn new_at(ptr_base: *mut std::os::raw::c_void, lp_name: &str) -> eyre::Result<Self> {
        let handle =
            crate::execute::hopper_create_file_mapping(0, 0x100000, lp_name.as_ptr() as u32)?;
        Self::from_id_at(handle, ptr_base)
    }

    /// Load shared memory by its SHMID at specific location of process memory
    fn from_id_at(
        handle: *mut std::os::raw::c_void,
        lp_addr: *mut std::os::raw::c_void,
    ) -> eyre::Result<Self> {
        let size = std::mem::size_of::<T>() as usize;
        let ptr = match crate::execute::hopper_map_view_of_file_ex(handle, 0, 0, 0, lp_addr) {
            Ok(ptr) => ptr as *mut T,
            Err(_) => {
                // crate::execute::hopper_unmap_view_of_file(ptr_base as crate::execute::PVOID);
                // crate::execute::hopper_map_view_of_file_ex(id,0,0,0,ptr_base as *mut std::os::raw::c_void).unwrap() as *mut T
                // eyre::bail!("fail to setup shared memory!");
                lp_addr as *mut T
            }
        };
        Ok(SharedMemory::<T> { handle, size, ptr })
    }

    /// Clear content at shared memory
    pub fn clear(&mut self) {
        unsafe { libc::memset(self.ptr as *mut libc::c_void, 0, self.size) };
    }

    /// Get unique key for environment
    pub fn get_env_var(&self) -> String {
        "".to_string()
    }
}

pub fn setup_shm<T: SHMable>() -> eyre::Result<SharedMemory<T>> {
    log::info!("setup {} shm for e9 runtime...", T::name());
    // let area_base = format!("{}_AREA_BASE\x00", crate::config::TASK_NAME);
    let lp_name = format!("{}_{}\x00", T::shmid_env_var(),crate::config::TASK_NAME);
    let shm = SharedMemory::<T>::new_at(T::ptr_base() as *mut std::os::raw::c_void, &lp_name)?;
    log::info!("setup {} shared memory success ! shm: {:?}, lp_name: {}", T::name(), shm, lp_name);
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
        write!(f, "{:?}, {}, {:p}", self.handle, self.size, self.ptr)
    }
}

impl<T> Drop for SharedMemory<T> {
    fn drop(&mut self) {
        crate::execute::hopper_unmap_view_of_file(self.ptr as crate::execute::Pvoid).unwrap();
        crate::execute::hopper_close_handle(self.handle).unwrap();
    }
}
