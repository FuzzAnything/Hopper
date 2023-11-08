use binary_info::BinaryInfo;
use eyre::{Context, ContextCompat, Result};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use clap::Parser;

mod cargo;
mod check;
mod config;
mod dwarf;
#[cfg(target_os = "linux")]
mod patch;
mod binary_info;

use config::*;

pub fn compile(config: &Config) -> Result<()> {
    log::info!("config: {:?}", config);
    fs::create_dir_all(&config.output).expect("fail to create output directory");
    let output = PathBuf::from(&config.output)
        .canonicalize()
        .expect("cononicalize output path fail");
    eyre::ensure!(!config.header.is_empty(), "require at least one header");
    eyre::ensure!(!config.library.is_empty(), "require at least one library");
    let header = if config.header.len() == 1 {
        let header = PathBuf::from(&config.header[0])
            .canonicalize()
            .expect("cononicalize header path fail");
        check::check_header(&header)?;
        header
    } else {
        concat_headers(&output, &config.header)?
    };

    let mut libraries = vec![];
    let mut func_list = vec![];
    for lib in &config.library {
        let lib = PathBuf::from(lib)
            .canonicalize()
            .expect("cononicalize library path fail");
        check::check_library(&lib)?;
        let lib_info = crate::binary_info::BinaryInfo::parse(&lib)?;
        let instrumented_lib = instrument(&lib, &output, config, &lib_info)?;
        libraries.push(instrumented_lib);
        func_list.extend(lib_info.func_list);
    }
    binary_info::save_func_list(&func_list, &output)?;
    cargo::cargo_install(libraries, &header, &output, config, func_list)?;
    Ok(())
}

fn instrument(library: &Path, output: &Path, config: &Config, lib_info: &BinaryInfo) -> Result<PathBuf> {
    let lib_name = library.file_name().context("fail to parse library name")?;
    let lib_name = check::output_lib_name(lib_name.to_str().context("fail cast as str")?);
    let output_lib = output.join(&lib_name);
    match config.instrument {
        InstrumentType::E9 => {
            #[cfg(target_os = "windows")]
            {
                eyre::ensure!(
                    check::check_file_contains(library, "E9PATCH"),
                    "The library should be instrumented by E9 in linux"
                );
                fs::copy(library, &output_lib).context("fail to copy library")?;
            }
            #[cfg(target_os = "linux")]
            patch::e9_instrument(library, &output_lib, lib_info)?;
        }
        InstrumentType::Llvm | InstrumentType::Cov => {
            fs::copy(library, &output_lib).context("fail to copy library")?;
        }
    }
    #[cfg(target_os = "linux")]
    patch::patchelf_set_so_name(&lib_name, output_lib.to_str().context("fail to be str")?)?;
    Ok(output_lib)
}


fn main() -> Result<()> {
    init_logger();
    let mut config = Config::parse();
    if check::check_llvm_runtime(&config.library) {
        config.instrument = InstrumentType::Llvm;
    }
    let ret = compile(&config);
    if let Err(e) = ret {
        log::error!("Meets error: {}", e);
        return Err(e); 
    }

    Ok(())
}



fn init_logger() {
    let mut config_builder = simplelog::ConfigBuilder::new();
    config_builder.set_time_offset_to_local().unwrap();
    simplelog::CombinedLogger::init(vec![simplelog::TermLogger::new(
        simplelog::LevelFilter::Info,
        config_builder.build(),
        simplelog::TerminalMode::Mixed,
        simplelog::ColorChoice::Auto,
    )])
    .unwrap();
}

fn concat_headers(output: &Path, headers: &Vec<String>) -> Result<PathBuf> {
    let tmp_header = output.join("tmp.h");
    let mut content = String::new();
    for header in headers {
        let header = PathBuf::from(header)
            .canonicalize()
            .expect("cononicalize header path fail");
        check::check_header(&header)?;
        content.push_str(&format!("#include \"{}\"\n", header.to_str().unwrap()));
    }
    let mut f = std::fs::File::create(&tmp_header)?;
    f.write_all(content.as_bytes())?;

    Ok(tmp_header)
}
