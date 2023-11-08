use eyre::{ensure, ContextCompat, Result};
use std::{fs::File, path::Path};

#[cfg(target_os = "linux")]
static DYNAMIC_LIB_SUFFIX: &str = ".so";
#[cfg(target_os = "macos")]
static DYNAMIC_LIB_SUFFIX: &'static str = ".dylib";
#[cfg(target_os = "windows")]
static DYNAMIC_LIB_SUFFIX: &str = ".dll";
static STATIC_LIB_SUFFIX: &str = ".a";

static DYNAMIC_LIB_SUFFIX_PE: &str = ".dll";

pub fn check_header(header: &Path) -> Result<()> {
    ensure!(header.is_file(), "Header is not a file");
    ensure!(
        header.extension().context("Can't find header extension")? == "h",
        "Header is not end with .h"
    );
    Ok(())
}

pub fn check_library(library: &Path) -> Result<()> {
    ensure!(library.is_file(), "Library is not a file");

    let file_name = library
        .file_name()
        .context("Can't find library file name")?
        .to_str()
        .context("fail to convert to str")?;
    ensure!(
        file_name.starts_with("lib"),
        "Library is not start with lib"
    );
    ensure!(
        file_name.contains(DYNAMIC_LIB_SUFFIX)
            || file_name.ends_with(STATIC_LIB_SUFFIX)
            || file_name.ends_with(DYNAMIC_LIB_SUFFIX_PE),
        "Library does not contain `.so` or `.a` or `.dylib`"
    );
    Ok(())
}

pub fn output_lib_name(file: &str) -> String {
    if let Some(index) = file.find(DYNAMIC_LIB_SUFFIX) {
        let lib = &file[..index];
        return format!("{lib}_fuzz{DYNAMIC_LIB_SUFFIX}");
    }
    file.to_string()
}

pub fn check_llvm_runtime(libraries: &[String]) -> bool {
    libraries
        .iter()
        .any(|l| check_file_contains(l, "HOOPER_LLVM_MARK"))
}

pub fn check_file_contains(target: &str, s: &str) -> bool {
    let file = File::open(target).unwrap_or_else(|_| panic!("Unable to open file: {target}"));
    let f = unsafe {
        memmap::MmapOptions::new()
            .map(&file)
            .expect("unable to mmap file")
    };
    twoway::find_bytes(&f[..], s.as_bytes()).is_some()
}
