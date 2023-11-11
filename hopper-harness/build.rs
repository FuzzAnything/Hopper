extern crate bindgen;

use std::path::PathBuf;
use std::{env, fs};

use bindgen::callbacks;

#[derive(Debug)]
pub struct HopperCallbacks {}

const IGNORE_MACROS: &[&str] = &[
    "FE_DIVBYZERO",
    "FE_DOWNWARD",
    "FE_INEXACT",
    "FE_INVALID",
    "FE_OVERFLOW",
    "FE_TONEAREST",
    "FE_TOWARDZERO",
    "FE_UNDERFLOW",
    "FE_UPWARD",
    "FP_INFINITE",
    "FP_INT_DOWNWARD",
    "FP_INT_TONEAREST",
    "FP_INT_TONEARESTFROMZERO",
    "FP_INT_TOWARDZERO",
    "FP_INT_UPWARD",
    "FP_NAN",
    "FP_NORMAL",
    "FP_SUBNORMAL",
    "FP_ZERO",
    "IPPORT_RESERVED",
];

impl HopperCallbacks {
    fn new() -> Self {
        Self {}
    }
}

impl callbacks::ParseCallbacks for HopperCallbacks {
    /// This will be called on every file inclusion, with the full path of the included file.
    /// Tell cargo to invalidate the built crate whenever any of the included header files changed.
    fn include_file(&self, filename: &str) {
        println!("cargo:rerun-if-changed={filename}");
    }

    /// This function will be run on every macro that is identified.
    fn will_parse_macro(&self, name: &str) -> callbacks::MacroParsingBehavior {
        if IGNORE_MACROS.contains(&name) {
            callbacks::MacroParsingBehavior::Ignore
        } else {
            callbacks::MacroParsingBehavior::Default
        }
    }

    /// This function will run for every extern variable and function. The returned value determines
    /// the name visible in the bindings.
    fn generated_name_override(&self, _item_info: callbacks::ItemInfo<'_>) -> Option<String> {
        None
    }

    /// This function will run for every extern variable and function. The returned value determines
    /// the link name in the bindings.
    fn generated_link_name_override(&self, _item_info: callbacks::ItemInfo<'_>) -> Option<String> {
        None
    }

    /// The integer kind an integer macro should have, given a name and the
    /// value of that macro, or `None` if you want the default to be chosen.
    fn int_macro(&self, _name: &str, _value: i64) -> Option<callbacks::IntKind> {
        None
    }

    /// This will be run on every string macro. The callback cannot influence the further
    /// treatment of the macro, but may use the value to generate additional code or configuration.
    fn str_macro(&self, _name: &str, _value: &[u8]) {}

    /// This will be run on every function-like macro. The callback cannot
    /// influence the further treatment of the macro, but may use the value to
    /// generate additional code or configuration.
    ///
    /// The first parameter represents the name and argument list (including the
    /// parentheses) of the function-like macro. The second parameter represents
    /// the expansion of the macro as a sequence of tokens.
    fn func_macro(&self, _name: &str, _value: &[&[u8]]) {}

    /// Allows to rename an enum variant, replacing `_original_variant_name`.
    fn enum_variant_name(
        &self,
        _enum_name: Option<&str>,
        _original_variant_name: &str,
        _variant_value: callbacks::EnumVariantValue,
    ) -> Option<String> {
        None
    }

    /// Allows to rename an item, replacing `_original_item_name`.
    fn item_name(&self, _original_item_name: &str) -> Option<String> {
        None
    }

    /// This will be called every time `bindgen` reads an environment variable whether it has any
    /// content or not.
    fn read_env_var(&self, _key: &str) {}

    /*
    fn add_derives(&self, _name: &str) -> Vec<String> {
        vec![
            "Serialize".to_string(),
            "Deserialize".to_string(),
            // "Fuzz".to_string(),
        ]
    }
    */
}

#[cfg(target_os = "linux")]
static DYNAMIC_LIB_SUFFIX: &str = ".so";
#[cfg(target_os = "macos")]
static DYNAMIC_LIB_SUFFIX: &'static str = ".dylib";
#[cfg(target_os = "windows")]
static DYNAMIC_LIB_SUFFIX: &str = ".dll";
static STATIC_LIB_SUFFIX: &str = ".a";

fn link_libraries() {
    // Tell cargo to tell rustc to link shared library.
    let library_env = env::var("HOPPER_LIBRARY").unwrap();
    let library_list = library_env.split(',');
    for library in library_list {
        let library_path = PathBuf::from(library);
        let dir = library_path.parent().unwrap().to_string_lossy();
        let lib = library_path.file_name().unwrap().to_string_lossy();
        #[cfg(target_os = "linux")]
        let lib = lib.trim_start_matches("lib");
        let (lib, is_static) = if let Some(s) = lib.strip_suffix(STATIC_LIB_SUFFIX) {
            (s, true)
        } else {
            let (lib, _) = lib
                .split_once(DYNAMIC_LIB_SUFFIX)
                .unwrap_or_else(|| panic!("library should end with `{DYNAMIC_LIB_SUFFIX}`"));
            (lib, false)
        };
        println!("cargo:warning=dir={dir}, lib={lib}");
        if is_static {
            println!("cargo:rustc-link-lib=static={lib}");
        } else {
            println!("cargo:rustc-link-lib=dylib={lib}");
            #[cfg(target_os = "linux")]
            println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
        }
        println!("cargo:rustc-link-search=native={dir}");
    }
    #[cfg(target_os = "linux")]
    println!("cargo:rustc-link-arg=-Wl,--allow-shlib-undefined");
}

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    if env::var("HOPPER_LIBRARY").is_err() {
        fs::write(out_path.join("fuzz_extend.rs"), "".as_bytes()).expect("Unable to write file");
        return;
    }
    link_libraries();
    let header_path = env::var("HOPPER_HEADER").unwrap();
    println!("cargo:rerun-if-changed={header_path}");
    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let mut builder = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(header_path)
        // Callback during parsing
        .parse_callbacks(Box::new(HopperCallbacks::new()))
        // Disable derive default
        .derive_default(false)
        // Should have debug trait
        .derive_debug(true)
        // If debug can't derived, we impl it
        .impl_debug(true)
        // use NewType for enum
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_bitfield: false,
            is_global: false,
        })
        // default blocklist
        .blocklist_function("__.*")
        .blocklist_function("strtold")
        // Diable layout test
        .layout_tests(false);

    if let Some(allowlist) = option_env!("HOPPER_FUNC_ALLOW_LIST") {
        builder = builder.allowlist_function("fopen");
        let list: std::str::Split<char> = allowlist.split(',');
        for item in list {
            builder = builder.allowlist_function(item);
        }
    }
    if let Some(blacklist) = option_env!("HOPPER_FUNC_BLACKLIST") {
        let list: std::str::Split<char> = blacklist.split(',');
        for item in list {
            builder = builder.blocklist_function(item);
        }
    }
    if let Some(blacklist) = option_env!("HOPPER_TYPE_BLACKLIST") {
        let list = blacklist.split(',');
        for item in list {
            builder = builder.blocklist_type(item);
        }
    }
    if let Some(blacklist) = option_env!("HOPPER_ITEM_BLACKLIST") {
        let list = blacklist.split(',');
        for item in list {
            builder = builder.blocklist_item(item);
        }
    }
    if let Some(include_search_paths) = option_env!("HOPPER_INCLUDE_SEARCH_PATH") {
        let list = include_search_paths.split(':');
        for item in list {
            let arg = format!("-I{item}");
            println!("cargo:warning=add_search_path={item}");
            builder = builder.clang_arg(arg.as_str());
        }
    }

    if let Some(opaque_list) = option_env!("HOPPER_CUSTOM_OPAQUE_LIST") {
        let list = opaque_list.split(',');
        for item in list {
            println!("cargo:warning=`{item}` is custom opaque");
            builder = builder.opaque_type(item);
        }
    }
    // default opaque type
    builder = builder.opaque_type("_IO_FILE");

    // enable the verbose flag for clang
    // builder = builder.clang_arg("-v");

    // Finish the builder and generate the bindings.
    let bindings = builder
        .generate()
        // https://github.com/rust-lang/rust-bindgen/pull/1846
        // dynamic_library_name()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    // sbindings.write_to_file(out_path.join("bindings.rs")).expect("Couldn't write bindings!");

    // Enhance FFI binding code for hopper
    hopper_derive_impl::set_compiler_env();
    let fuzz_gen = hopper_derive_impl::derive_bindings(&bindings.to_string());
    let raw_content = fuzz_gen.to_string();
    // Format code by rustfmt
    let fmt_content = hopper_derive_impl::format::rustfmt_generated_string(&raw_content)
        .expect("fail to format content");
    // Write to the fuzz_extend.rs file.
    fs::write(out_path.join("fuzz_extend.rs"), fmt_content.as_bytes())
        .expect("Unable to write file");
}
