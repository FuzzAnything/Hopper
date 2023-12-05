//! Linux specification
//! set shared libary's soname

use std::{env, path::PathBuf, process::Command};

use eyre::{ensure, Context, Result};

use crate::binary_info::BinaryInfo;

fn patchelf_path() -> Result<PathBuf> {
    if let Ok(path) = env::var("HOPPER_PATH") {
        return Ok(format!("{}/patchelf", &path).into());
    }
    let exe_dir = env::current_dir()?;
    Ok(exe_dir)
}

pub fn patchelf_set_so_name(lib_name: &str, path: &str) -> Result<()> {
    let patchelf = patchelf_path()?;
    log::info!(
        "patchelf cmd: {:?}, lib_name: {:?}, path: {:}",
        patchelf,
        lib_name,
        path
    );
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

pub fn remove_prev_needed(input_libs: &[String], path: &str, lib_info: &BinaryInfo) -> Result<()> {
    if input_libs.len() == 1 {
        return Ok(());
    }
    let patchelf = patchelf_path()?;
    let needed_names: Vec<String> = input_libs
        .iter()
        .map(|l| {
            format!(
                "{}",
                PathBuf::from(l).file_name().unwrap().to_string_lossy()
            )
        })
        .collect();

    log::info!("lib needed: {:?}", lib_info.needed);

    for name in &needed_names {
        if let Some(exist) = lib_info.needed.iter().find(|l| l.contains(name)) {
            log::info!("try remove need {exist} in {path:?}..");
            let mut child = Command::new(&patchelf)
                .arg("--remove-needed")
                .arg(exist)
                .arg(path)
                .spawn()
                .context("Fail to invoke patchelf")?;
            let status = child.wait()?;
            ensure!(status.success(), "patchelf remove needed serror");
        }
    }

    Ok(())
}

/*
pub fn patchelf_set_so_name2(lib_name: &str, path: &str) -> eyre::Result<()> {
    let suc = patchelf::PatchElf::config()
        .input(path)
        .set_soname(lib_name)
        .patch();

    eyre::ensure!(suc, "fail to set soname via patchelf");
    Ok(())
}
*/
