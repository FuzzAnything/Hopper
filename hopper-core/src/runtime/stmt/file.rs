//! Helper statement
//! provide some built-in usages, e.g. crate a file with buffer

use std::{ffi::CString, io::Write};

use eyre::ContextCompat;

use super::*;
use crate::runtime::*;

#[derive(Debug)]
pub struct FileStmt {
    pub ident: String,
    pub file: Option<FuzzObject>,
    pub buf_stmt: Option<StmtIndex>,
    pub is_mut: bool,
    pub is_fd: bool,
    // pub name: Option<String>,
}

impl FileStmt {
    pub fn new(ident: &str, is_mut: bool, is_fd: bool) -> Self {
        Self {
            ident: ident.to_string(),
            file: None,
            buf_stmt: None,
            is_mut,
            is_fd,
            // name: None,
        }
    }

    pub fn set_buf_index(&mut self, index: StmtIndex) {
        self.buf_stmt = Some(index);
    }

    pub fn get_file_name(&self) -> String {
        // if let Some(name) = &self.name {
        //    return name.to_string();
        // }
        let f = format!("file_{}", &self.ident);
        if let Some(i) = &self.buf_stmt {
            return format!("{}_{}", f, i.get());
        }
        f
    }
}

#[repr(transparent)]
#[derive(Debug, Default, Clone)]
pub struct FileFd(libc::c_int);

impl FileFd {
    pub fn new(file_name: *const i8, _index: usize) -> Self {
        #![allow(clippy::not_unsafe_ptr_arg_deref)]
        #[cfg(target_family = "unix")]
        unsafe {
            let fd = libc::open(file_name, libc::O_RDWR | libc::O_APPEND);
            Self(fd)
        }
        #[cfg(target_os = "windows")]
        unimplemented!("should use HANDLE in windows")
    }
    pub fn inner(&self) -> i32 {
        self.0
    }
}

impl Drop for FileFd {
    fn drop(&mut self) {
        if self.0 > 0 {
            #[cfg(target_family = "unix")]
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

impl StmtView for FileStmt {
    const KEYWORD: &'static str = "file";

    fn eval(
        &mut self,
        used_stmts: &mut [IndexedStmt],
        _resource_states: &mut ResourceStates,
    ) -> eyre::Result<()> {
        let temp_file = crate::config::tmp_file_path(&self.get_file_name());
        crate::log!(trace, "crate file: {:?}", temp_file);
        if let Some(index) = &self.buf_stmt {
            let stmt = &used_stmts[index.get()].stmt;
            let mut f = std::fs::File::create(&temp_file)?;
            if let Some(v) = stmt.get_value() {
                if crate::config::USE_CANARY {
                    let buf = v
                        .downcast_ref::<CanarySlice<u8>>()
                        .context("downcast buf")?;
                    f.write_all(buf.as_slice())?;
                } else {
                    let buf = v.downcast_ref::<Vec<u8>>().context("downcast buf")?;
                    f.write_all(buf.as_slice())?;
                };
            }
        }
        let file_name = CString::new(temp_file.to_string_lossy().to_string())?;
        let ptr = file_name.into_raw();
        crate::log!(trace, "file name ptr: {:?}", ptr);
        if self.is_fd {
            self.file = Some(Box::new(FileFd::new(ptr, used_stmts.len())));
        } else if self.is_mut {
            self.file = Some(Box::new(FuzzMutPointer::new(ptr)) as Box<dyn ObjFuzzable>);
        } else {
            self.file = Some(Box::new(FuzzConstPointer::new(ptr)) as Box<dyn ObjFuzzable>);
        }
        Ok(())
    }

    fn get_value(&self) -> Option<&FuzzObject> {
        self.file.as_ref()
    }
}

impl CloneProgram for FileStmt {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        let buf_stmt = self.buf_stmt.clone_with_program(program);
        Self {
            ident: self.ident.clone(),
            file: None,
            buf_stmt,
            is_mut: self.is_mut,
            is_fd: self.is_fd,
            // name: self.name.clone(),
        }
    }
}

impl From<FileStmt> for FuzzStmt {
    fn from(stmt: FileStmt) -> Self {
        FuzzStmt::File(Box::new(stmt))
    }
}

impl Serialize for FileStmt {
    fn serialize(&self) -> eyre::Result<String> {
        let mut extra_sym = "";
        if self.is_fd {
            extra_sym = "fd ";
        } else if self.is_mut {
            extra_sym = "mut ";
        }
        Ok(format!(
            "{} {}: {}{}",
            Self::KEYWORD,
            self.ident,
            extra_sym,
            self.buf_stmt.serialize()?
        ))
    }
}

impl Deserialize for FileStmt {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        // de.strip_token(Self::KEYWORD);
        let ident = de.next_token_until(":")?;
        let mut is_mut = false;
        let mut is_fd = false;
        if de.strip_token("mut ") {
            is_mut = true;
        }
        if de.strip_token("fd ") {
            is_fd = true;
        }
        let buf_stmt = Option::<StmtIndex>::deserialize(de)?;
        let mut file_stmt = Self::new(ident, is_mut, is_fd);
        file_stmt.buf_stmt = buf_stmt;
        /*
        if de.strip_token(",") {
            de.trim_start();
            let name = de.buf.to_string();
            file_stmt.name = Some(name);
        }
        */
        Ok(file_stmt)
    }
}

/// Just some code to make FileFd to be Fuzzable
impl ObjFuzzable for FileFd {}
impl ObjValue for FileFd {}
impl ObjType for FileFd {}
impl ObjectTranslate for FileFd {
    fn translate_obj_to_c(
        &self,
        _state: &ObjectState,
        _program: &FuzzProgram,
    ) -> eyre::Result<String> {
        unreachable!("can not translate fd");
    }
}
impl Serialize for FileFd {
    fn serialize(&self) -> eyre::Result<String> {
        unreachable!("can not serialize fd");
    }
}
impl ObjectSerialize for FileFd {
    fn serialize_obj(&self, _state: &ObjectState) -> eyre::Result<String> {
        unreachable!("can not serialize fd");
    }
}
