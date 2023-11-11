//! Linux specification
//! set shared libary's soname

use std::{
    env,
    path::PathBuf,
    process::Command,
};

use eyre::{ensure, Context, Result};

fn patchelf_path() -> Result<PathBuf> {
    if let Ok(path) = env::var("HOPPER_PATH") {
        return Ok(format!("{}/patchelf", &path).into());
    }
    let exe_dir = env::current_dir()?;
    Ok(exe_dir)
}

pub fn patchelf_set_so_name(lib_name: &str, path: &str) -> Result<()> {
    let patchelf = patchelf_path()?;
    log::info!("patchelf cmd: {:?}, lib_name: {:?}, path: {:}",  patchelf, lib_name, path);
    let mut child = Command::new(&patchelf)
        .arg("--set-soname")
        .arg(lib_name)
        .arg(path)
        .spawn()
        .context("Fail to invoke patchelf")?;

    log::info!("start set soname ..");

    let status = child.wait()?;
    ensure!(status.success(), "patchelf set soname error");
    log::info!("patchelf set soname done");

    Ok(())
}