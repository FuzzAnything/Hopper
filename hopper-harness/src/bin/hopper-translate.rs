use clap::Parser;
use hopper::Translate;
use std::io::Write;

/// Hopper - fuzz libraries fully automatically
#[derive(Parser, Debug)]
#[clap(name = "hopper-translate")]
#[clap(version = "1.0.0", author = "Tencent")]
pub struct TranslateConfig {
    /// Path of header file of library
    #[clap(long, value_parser)]
    pub header: String,

    /// Output directory of harness
    #[clap(long, value_parser)]
    pub input: String,

    /// Output directory of harness
    #[clap(long, value_parser)]
    pub output: Option<String>,
}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    hopper_harness::hopper_extend();
    flexi_logger::Logger::try_with_env_or_str("trace")?.start()?;
    let config = TranslateConfig::parse();
    log::info!("config: {:?}", config);
    // hopper::check_gadgets().unwrap();
    let buf = std::fs::read_to_string(&config.input)?;
    let program = hopper::read_program(&buf, false)?;
    let out = program.translate_to_c()?;
    let include_header = format!("#include \"{}\"\n", config.header);
    let mut out = include_header + &out;
    fix_error(&mut out, &config.header)?;
    log::info!("{}", out);
    let f_name = if let Some(out_f) = config.output {
        out_f
    } else {
        config.input + ".c"
    };
    let mut f = std::fs::File::create(&f_name)?;
    f.write_all(out.as_bytes())?;
    log::info!("please run: gcc -g -I. -L. -lyourlib {}", f_name);
    Ok(())
}

fn fix_error(code: &mut String, header: &str) -> eyre::Result<()> {
    use std::io::BufRead;
    static TMP_CODE_FILE: &str = "/tmp/hopper_tmp.c";
    static TMP_OUT_FILE: &str = "/tmp/hopper_tmp.out";
    log::info!("try to fix struct type error..");
    let header_path = std::path::Path::new(header);
    std::fs::write(TMP_CODE_FILE, &code)?;
    let mut args = vec![
        TMP_CODE_FILE,
        "-g",
        "-c",
        "-I.",
        "-o",
        TMP_OUT_FILE,
    ];
    if let Some(header_dir) = header_path.parent() {
        args.push("-I");
        args.push(header_dir.to_str().unwrap());
        if let Some(hh_dir) = header_dir.parent() {
            args.push("-I");
            args.push(hh_dir.to_str().unwrap());
        }
    }
    if let Some(include_search_paths) = option_env!("HOPPER_INCLUDE_SEARCH_PATH") {
        let list = include_search_paths.split(':');
        for item in list {
            args.push("-I");
            args.push(item);
        }
    }
    let ret = std::process::Command::new("clang")
        .args(args)
        .output()?;
    let mut struct_list = vec![];
    for line in ret.stdout.lines() {
        let line = line?;
        if line.contains(r"use \xe2\x80\x98struct\xe2\x80\x99 keyword to refer to the") || line.contains(r"unknown type name") {
            struct_list.push(get_struct_name(&line)?);
        }
    }
    if struct_list.is_empty() {
        return Ok(());
    }
    for s in struct_list {
        *code = code.replace(&format!("{s} "), &format!("struct {s} "));
        log::warn!("replace `{s}` to `struct {s}`");
    }

    Ok(())
}


fn get_struct_name(line: &str) -> eyre::Result<String> {
    static LEFT_MARK: &str = r"\xe2\x80\x98";
    static RIGHT_MAKR: &str = r"\xe2\x80\x99";
    if let Some(l) = line.find(LEFT_MARK) {
        let rest = &line[l + LEFT_MARK.len() ..];
        if let Some(r) = line.find(RIGHT_MAKR) {
            return Ok(rest[..r].to_string());
        }
    }
    eyre::bail!("Fail to find struct name");
}