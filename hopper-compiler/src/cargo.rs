use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    process::Command,
};

use eyre::{bail, ensure, Context, ContextCompat, Result};

use crate::{config::Config, binary_info::FuncInfo};

fn cargo_path() -> PathBuf {
    if let Ok(path) = env::var("CARGO") {
        return path.into();
    }
    "cargo".into()
}

fn hopper_harness_path() -> Result<PathBuf> {
    if let Ok(path) = env::var("HOPPER_HARNESS_ROOT") {
        return Ok(path.into());
    }
    let crate_path: Option<&'static str> = option_env!("CARGO_MANIFEST_DIR");
    if let Some(p) = crate_path {
        return Ok(PathBuf::from(p).parent().unwrap().join("hopper-harness"));
    }

    bail!("Can't find harness path")
}

fn task_name(library: &str) -> &str {
    #[cfg(target_family = "unix")]
    let (_, lib) = library.rsplit_once('/').unwrap();
    #[cfg(target_os = "windows")]
    let (_, lib) = library.rsplit_once('\\').unwrap();
    let (lib, _) = lib.split_once('.').unwrap();
    log::info!("task name: {}", lib);
    lib
}

fn convert_canonicalized_path(path: &Path) -> String {
    let p = path.display().to_string();
    // https://stackoverflow.com/questions/50322817/how-do-i-remove-the-prefix-from-a-canonical-windows-path
    #[cfg(target_os = "windows")]
    if let Some(next) = p.strip_prefix(r#"\\?\"#) {
        return next.to_string();
    }
    p
}

pub fn cargo_install(
    libraries: Vec<PathBuf>,
    header: &Path,
    out: &Path,
    config: &Config,
    func_list: Vec<FuncInfo>,
) -> Result<()> {
    let cargo = cargo_path();
    let harness_path = hopper_harness_path()?;
    let mut envs = HashMap::new();
    let out_dir = convert_canonicalized_path(out);
    // envs.insert("INSTRUMENT_TYPE", instrument_type.to_str());
    let library_list: Vec<&str> = libraries.iter().map(|l| l.to_str().unwrap()).collect();
    let library = library_list.join(",");
    let header = header.to_str().context("Fail to convert header as str")?;
    let func_list: Vec<&str> = func_list.iter().map(|f| f.name.as_str()).collect();
    let func_allow = func_list.join(",");
    envs.insert("HOPPER_HEADER", header);
    envs.insert("HOPPER_LIBRARY", &library);
    envs.insert("HOPPER_TASK", task_name(&library));
    envs.insert("HOPPER_OUT_DIR", &out_dir);
    if !func_allow.is_empty() {
        envs.insert("HOPPER_FUNC_ALLOW_LIST", &func_allow);
    }
    let mut quiet_option = "--verbose";
    if config.quiet {
        envs.insert("RUSTFLAGS", "-Awarnings");
        quiet_option = "--quiet";
    }
    let mut features = format!("{}_mode", config.instrument.as_str());
    if env::var("HOPPER_TESTSUITE").is_ok() {
        features.push_str(",testsuite");
    }
    let args = [
        "install",
        quiet_option,
        "--features",
        &features,
        "--force",
        "--path",
        &harness_path.to_string_lossy(),
        "--target-dir",
        &out_dir,
        "--root",
        &out_dir,
    ];
    log::info!(
        "cargo cmd: {:?} , args: {:?}, envs: {:?}",
        &cargo,
        args.join(" "),
        envs
    );
    let mut child = Command::new(&cargo)
        .args(args)
        .envs(envs)
        .spawn()
        .context("Fail to invoke cargo install")?;

    log::info!("start compiling harness by cargo ..");

    let status = child.wait()?;
    ensure!(status.success(), "cargo install error");

    log::info!("compiling harness done");

    // mac should set link library by `install_name_tool`
    #[cfg(target_os = "macos")]
    {
        let (_, library_file) = library
            .rsplit_once("/")
            .context("fail to get library file")?;
        let harness_bin = out.join("bin/hopper-harness");
        let fuzzer_bin = out.join("bin/hopper-fuzzer");
        fn change_link_lib(lib_origin: &str, lib_new: &str, executable: &str) -> Result<()> {
            let output = std::process::Command::new("install_name_tool")
                .args(["-change", &lib_origin, &lib_new, executable])
                .output()
                .context("Failed to start install_name_tool")?;
            ensure!(
                output.status.success(),
                "install_name_tool failed: {:#?}",
                output
            );
            Ok(())
        }
        change_link_lib(
            library_file,
            library,
            harness_bin.to_str().context("fail to convert as str")?,
        )?;
        change_link_lib(
            library_file,
            library,
            fuzzer_bin.to_str().context("fail to convert as str")?,
        )?;
    }

    Ok(())
}
