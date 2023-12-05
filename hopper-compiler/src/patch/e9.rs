#![allow(dead_code)]
//! Run e9patch instrumentation command
//! [OPTIONS] library [e9tool-OPTIONS]
//! OPTIONS:
//! -Oblock=never,default,always
//!   Apply bad block optimization.
//! -Oselect=never,default,always
//!   Apply selection optimization.
//! -d, --debug
//!   Enable debugging output.
//! --counter=classic,neverzero,saturated
//!
//! E9Patch is not support static library
//!

use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    process::Command,
};

use eyre::{ensure, Context, Result};

use crate::binary_info::BinaryInfo;

pub fn e9_instrument(library: &Path, output_lib: &Path, lib_info: &BinaryInfo) -> Result<()> {
    let e9_dir = e9_dir()?;
    let e9_tool = e9_dir.join("e9tool");
    ensure!(
        e9_tool.exists(),
        format!("e9tool is not found in {:?}", &e9_tool)
    );
    let lib_type = lib_info.lib_type;
    let cov_plugin_path = e9_dir.join(format!("hopper-e9-plugin-{lib_type}.so"));
    let cov_plugin = cov_plugin_path.to_string_lossy();
    let instr_plugin_path = e9_dir.join(format!("hopper-instr-plugin-{lib_type}.so"));
    let instr_plugin = instr_plugin_path.to_string_lossy();
    let hopper_rt_path = e9_dir.join(format!("hopper-e9-rt-{lib_type}"));
    let hopper_rt = hopper_rt_path.to_string_lossy();

    let mut envs = HashMap::new();
    envs.insert("E9AFL_PATH", e9_dir.to_string_lossy().to_string());
    envs.insert("E9AFL_COUNTER", "saturated".to_string());
    if let Ok(str) = env::var("HOPPER_MAP_SIZE_POW2") {
        envs.insert("HOPPER_MAP_SIZE_POW2", str);
    }
    if let Ok(str) = env::var("HOPPER_INST_RATIO") {
        envs.insert("HOPPER_INST_RATIO", str);
    }
    // envs.insert("E9AFL_DEBUG", "default".to_string());
    // envs.insert("E9AFL_OBLOCK", "default".to_string());
    // envs.insert("E9AFL_OSELECT", "default".to_string());
    // envs.insert("E9AFL_COUNTER", "default".to_string());
    let mut args = vec![];
    let conf_args = [
        "-E",
        "\".plt\"",
        "-E",
        "\".plt.got\"",
        "-O2",
        "--option",
        "--mem-granularity=4096",
        // "--debug",
        // --seed
        "-o",
        &format!("{}", &output_lib.to_string_lossy()),
    ];
    args.extend_from_slice(&conf_args);

    let plugin_pattern = [
        "-M",
        &format!("plugin(\"{cov_plugin}\").match()"),
        "-P",
        &format!("plugin(\"{cov_plugin}\").patch()"),
        "-M",
        &format!("plugin(\"{instr_plugin}\").match()"),
        "-P",
        &format!("plugin(\"{instr_plugin}\").patch()"),
    ];
    args.extend_from_slice(&plugin_pattern);
    let indiret_call_pat = [
        "-M",
        "call and op[0].type != imm",
        "-P",
        &format!("before entry_indirect(offset, op[0], &rdi, rsi)@{hopper_rt}"),
        "-M",
        "jump and op[0].type != imm",
        "-P",
        &format!("before entry_indirect(offset, op[0], &rdi, rsi)@{hopper_rt}"),
        "-M",
        "I[-1].call and I[-1].op[0].type != imm",
        "-P",
        &format!("before exit_indirect(offset, rax)@{hopper_rt}"),
    ];
    args.extend_from_slice(&indiret_call_pat);
    // use hook.rs instead
    // e9_fn_hook(hopper_rt.as_ref(), lib_info, &mut args);

    let e9_exclude: Vec<String> = lib_info
        .list_exclude_patch_range()
        .iter()
        .map(|range| format!("-E 0x{:02X}..0x{:02x}", range.0, range.1))
        .collect();
    for exclude in e9_exclude.iter() {
        args.push(exclude);
    }

    // add_instrument_patterns(&mut args, library, &e9_dir)?;
    let lib_args = ["--", &format!("{}", &library.to_string_lossy())];
    args.extend_from_slice(&lib_args);

    log::info!(
        "e9 cmd: {:?}, args: {}, envs: {:?}",
        e9_tool,
        args.join(" "),
        envs
    );
    let mut child = Command::new(&e9_tool)
        .args(args)
        .envs(envs)
        .spawn()
        .context("Fail to invoke e9")?;

    log::info!("start instrument library by e9 ..");
    let status = child.wait()?;
    ensure!(status.success(), "e9 instrumenit error");
    log::info!("e9 instrument done");
    if lib_type == "pe" {
        log::warn!("copy it to windows and fuzz!");
        std::process::exit(0);
    }
    Ok(())
}

fn e9_dir() -> Result<PathBuf> {
    if let Ok(path) = env::var("HOPPER_PATH") {
        return Ok(path.into());
    }
    let exe_dir = env::current_dir()?;
    Ok(exe_dir)
}

fn e9_fn_hook(hopper_rt: &str, lib_info: &BinaryInfo, args: &mut Vec<&str>) {
    let free_pat = [
        "-M",
        "call and target == &free",
        "-P",
        format!("before entry_free(offset, &rdi)@{hopper_rt}").leak()
    ];
    let malloc_pat = [
        "-M",
        "call and target == &malloc",
        "-P",
        format!("replace hook_malloc(offset, rdi, &rax)@{hopper_rt}").leak(),
    ];
    let calloc_pat = [
        "-M",
        "call and target == &calloc",
        "-P",
        format!("replace hook_calloc(offset, rdi, rsi, &rax)@{hopper_rt}").leak(),
    ];
    let realloc_pat = [
        "-M",
        "call and target == &realloc",
        "-P",
        format!("replace hook_realloc(offset, rdi, rsi, &rax)@{hopper_rt}").leak(),
    ];
    let fopen_pat = [
        "-M",
        "call and target == &fopen",
        "-P",
        format!("before entry_fopen(offset, rdi, rsi)@{hopper_rt}").leak(),
    ];
    let open_pat = [
        "-M",
        "call and target == &open",
        "-P",
        format!("before entry_open(offset, rdi, rsi)@{hopper_rt}").leak(),
    ];
    let open64_pat = [
        "-M",
        "call and target == &open64",
        "-P",
        format!("before entry_open(offset, rdi, rsi)@{hopper_rt}").leak(),
    ];
    let close_pat = [
        "-M",
        "call and target == &close",
        "-P",
        format!("before entry_close(offset, &rdi)@{hopper_rt}").leak(),
    ];
    let creat_pat = [
        "-M",
        "call and target == &creat",
        "-P",
        format!("before entry_creat(offset, rdi)@{hopper_rt}").leak(),
    ];
    let fdopen_pat = [
        "-M",
        "call and target == &fdopen",
        "-P",
        format!("before entry_fdopen(offset, &rdi, rsi)@{hopper_rt}").leak(),
    ];
    let lseek_pat = [
        "-M",
        "call and target == &lseek",
        "-P",
        format!("before entry_lseek(offset, &rdi)@{hopper_rt}").leak(),
    ];
    let lseek64_pat = [
        "-M",
        "call and target == &lseek64",
        "-P",
        format!("before entry_lseek(offset, &rdi)@{hopper_rt}").leak(),
    ];
    let read_pat = [
        "-M",
        "call and target == &\"read\"",
        "-P",
        format!("before entry_read(offset, &rdi)@{hopper_rt}").leak(),
    ];
    let write_pat = [
        "-M",
        "call and target == &\"write\"",
        "-P",
        format!("before entry_write(offset, &rdi)@{hopper_rt}").leak(),
    ];
    // log::info!("lib funcs: {:?}", funcs);
    if lib_info.contain_func("free") {
        args.extend_from_slice(&free_pat);
    }
    if lib_info.contain_func("malloc") {
        args.extend_from_slice(&malloc_pat);
    }
    if lib_info.contain_func("calloc") {
        args.extend_from_slice(&calloc_pat);
    }
    if lib_info.contain_func("realloc") {
        args.extend_from_slice(&realloc_pat);
    }
    // TODO: strdup
    if lib_info.contain_func("fopen") {
        args.extend_from_slice(&fopen_pat);
    }
    if lib_info.contain_func("open") {
        args.extend_from_slice(&open_pat);
    }
    if lib_info.contain_func("close") {
        args.extend_from_slice(&close_pat);
    }
    if lib_info.contain_func("open64") {
        args.extend_from_slice(&open64_pat);
    }
    if lib_info.contain_func("creat") {
        args.extend_from_slice(&creat_pat);
    }
    if lib_info.contain_func("fdopen") {
        args.extend_from_slice(&fdopen_pat);
    }
    if lib_info.contain_func("lseek") {
        args.extend_from_slice(&lseek_pat);
    }
    if lib_info.contain_func("lseek64") {
        args.extend_from_slice(&lseek64_pat);
    }
    if lib_info.contain_func("read") {
        args.extend_from_slice(&read_pat);
    }
    if lib_info.contain_func("write") {
        args.extend_from_slice(&write_pat);
    }
}
