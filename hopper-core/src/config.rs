// --- Project setting ---
pub const TASK_NAME: &str = task_env_var();
pub const OUTPUT_DIR: &str = out_dir_env_var();
// Use canary or not
pub const USE_CANARY: bool = use_canary();
// Enable set function pointer
pub const ENABLE_SET_FN_POINTER: bool = enable_fn_pointer();
pub const FN_POINTER_PREFIX: &str = fn_pointer_name_prefix();
// Enable use infered contraints
pub const ENABLE_REFINE: bool = true;
// Enable infer abort crash
pub const ENABLE_INFER_ABORT: bool = true;
// enable mutate
pub const ENABLE_MUTATE: bool = true;
// enable effective arg
pub const ENABLE_EFF_ARG: bool = true;
// enable inter api infer
pub const ENABLE_INTER_API_LEARN: bool = true;

// --- SHM and branch config ---
#[cfg(feature = "fat_bucket")]
pub type BucketType = u16;
#[cfg(not(feature = "fat_bucket"))]
pub type BucketType = u8;
// Branch coverage map size
pub const BRANCHES_POW2: usize = map_size_pow2_var();
pub const BRANCHES_SIZE: usize = 1 << BRANCHES_POW2;
// Fixed pointer for collected path, instructions
#[cfg(target_family = "unix")]
pub const SHM_PATH_BASE: u64 = 0x200000;
#[cfg(target_os = "windows")]
pub const SHM_PATH_BASE: u64 = 0x47e00000;
pub const SHM_INSTR_BASE: u64 = SHM_PATH_BASE + 0x100000;
#[cfg(target_os = "windows")]
pub const RAW_DATA_PTR: u64 = 0x46f00000;

// Size of area(a list) for collected cmp & memory related instructions
// or functions. If we modify these, please check asm.S and asm-win.S.
pub const CMP_LIST_AREA: usize = 0x80000;
pub const MEM_LIST_AREA: usize = 0x30000;
// Fixed pointer of arena memory for allocated objectes wrapped with canaries
pub const CANARY_PTR: *const u8 = (SHM_INSTR_BASE + 0x100000) as *const u8;
// Size of area of the arena memory
pub const CANARY_AREA_SIZE: usize = 0x100000;

// Name for shared memory
pub static PATH_SHMID_VAR: &str = "HOPPER_PATH_SHMID";
pub static INSTR_SHMID_VAR: &str = "HOPPER_INSTR_SHMID";

// --- Fork server ---
pub static FORK_SOCKET_PATH: &str = "HOPPER_SOCKET_PATH";

// Custom exit code
pub const FORK_ERROR_EXIT_CODE: i32 = 0x61;
pub const EXEC_ERROR_EXIT_CODE: i32 = 0x62;
pub const ASSERT_SILENT_EXIT_CODE: i32 = 0x63;
pub const ASSERT_ERROR_EXIT_CODE: i32 = 0x64;
pub const UAF_ERROR_EXIT_CODE: i32 = 0x65;
pub const TIMEOUT_CODE: i32 = 0x67;
pub const DOUBLE_FREE_ERROR_EXIT_CODE: i32 = 0x68;
pub const TEST_SUCCESS_EXIT_CODE: i32 = 0x69;

// --- Other ---
pub static TIMEOUT_LIMIT_VAR: &str = "HOPPER_TIMEOUT_LIMIT";
pub static CONSTRAINT_CONFIG: &str = "misc/constraint.config";
pub static SLICES_PATH: &str = "HOPPER_SLICES_PATH";
pub static ONLY_USE_SLICES_VAR: &str = "HOPPER_ONLY_SLICES";
// Hopper set all the malloced memory to a fixed content.
pub const UNINITIALIZED_MEMORY_MAGIC: usize = 0xFAFA_FAFA_FAFA_FAFA;
pub const DEFAULT_RIP_ADDR: u64 = 0xDEAD_BEEF_DEAD_BEEF;
pub const DEFAULT_SEGV_ADDR: u64 = 0xDEAD_BEEF_DEAD_BEEF;
pub const CMP_MAX_COUNTER: usize = 8;

// --- Depot ---
pub static CRASHES_DIR: &str = "crashes";
pub static MINIMIZED_CRASHES_DIR: &str = "minimized_crashes";
pub static HANGS_DIR: &str = "hangs";
pub static INPUTS_DIR: &str = "queue";
pub static MISC_DIR: &str = "misc";
pub static TMP_DIR: &str = "misc/tmp";
pub static REVIEW_DIR: &str = "misc/review";
pub static HARNESS_WORK_DIR: &str = "working";
pub const MAX_INPUT_SZIE: usize = 5000;
pub const MAX_QUEUE_SIZE: usize = 6000;

// --- Mutation ---
pub const ROUND_PILOT_NUM: usize = 256;
pub const ROUND_GENERATE_NUM: usize = 96;
pub const ROUND_MUTATE_NUM: usize = 384;
pub const ROUND_WARM_UP_NUM: usize = 256;
pub const MAX_STMTS_LEN: usize = 84;
pub const MAX_DEPTH: usize = 8;
pub const PILOT_MAX_DEPTH: usize = 3;
// Maximal length for vector we generated
pub const MIN_VEC_LEN: usize = 16;
pub const MAX_VEC_LEN: usize = 64;
// Times of re-running program after we find a new one
pub const RE_RUN_TIMES: usize = 5;
// Maximal number of failures in one round
pub const MAX_ROUND_FAIL_NUM: usize = 20;
// The maximal number of rounds if we has found nothing with single call
pub const ROUND_STUCK_NUM: usize = 50;
pub const ENABLE_APPEND_NEW_TARGET: bool = true;
/// --- Constraint ---
pub const MAX_RANGE_NUM: u64 = 4096;
pub const RESERVED_FD_MIN: i32 = 3;
pub const RESERVED_FD_MAX: i32 = 32;
pub const RESERVED_FD_HUGE: i32 = 1000;

// -----------------------------------------------------

use clap::{Parser, ValueEnum};
/// Configuration parsed from command line
#[derive(Debug, Clone, Parser, Default)]
#[clap(name = "hopper")]
#[clap(version = "1.0.0", author = "Tencent")]
pub struct Config {
    /// Function we want to fuzz. The pattern can be a function name,
    /// or a simple pattern, such as cJSON_*.
    /// If you has multiple pattern use `,` to join them, e.g cJSON_*,HTTP_*
    /// You can use @ prefix to limit it to only fuzz specific function.
    /// e.g. @JSON_parse, cJSON_*
    #[clap(long, value_parser)]
    pub func_pattern: Option<String>,
    /// Limitation of timeout, whose unit is seconds.
    #[clap(long, value_parser, default_value_t = 1)]
    pub timeout_limit: u64,
    /// Limitation of memory, whose unit is `MB`, and should > 10GB
    #[clap(long, value_parser)]
    pub mem_limit: Option<u64>,
    /// Select strategy
    #[clap(long, value_enum, value_parser, default_value = "sa")]
    pub select: SelectType,
    /// Custom rules for constraints or patterns
    #[clap(long, value_parser)]
    pub custom_rules: Option<String>,
    /// Taget function
    #[clap(skip)]
    pub func_target: Option<&'static str>,
    /// include function patterns
    #[clap(skip)]
    pub func_include: Vec<String>,
    /// Exclude function patterns
    #[clap(skip)]
    pub func_exclude: Vec<String>,
    /// Key functions
    #[clap(skip)]
    pub func_key: Vec<String>,
}

use eyre::Context;
use once_cell::sync::OnceCell;
use std::io::BufRead;

pub static mut CONFIG_INSTANCE: Option<Config> = None;

pub fn get_config() -> &'static Config {
    if let Some(c) = unsafe { &CONFIG_INSTANCE } {
        return c;
    }
    unsafe {
        CONFIG_INSTANCE = Some(Config::default());
    }
    unsafe { CONFIG_INSTANCE.as_ref().unwrap() }
}

pub fn get_config_mut() -> &'static mut Config {
    if let Some(c) = unsafe { &mut CONFIG_INSTANCE } {
        return c;
    }
    unsafe {
        CONFIG_INSTANCE = Some(Config::default());
    }
    unsafe { CONFIG_INSTANCE.as_mut().unwrap() }
}

pub fn parse_config() -> eyre::Result<()> {
    let mut config = Config::parse();
    config.set_func_pattern()?;
    if let Some(size) = config.mem_limit {
        if size < 10000 {
            eyre::bail!("the limitation for memory it too small! (< 10GB), since we enable canary and huge shm in our harness, we need much memory!");
        }
        if size == 0 {
            config.mem_limit = None;
        }
    }
    *get_config_mut() = config;
    Ok(())
}

impl Config {
    /// Match a function to check if it can be our candidates or not.
    pub fn match_func(&self, f_name: &str) -> bool {
        if let Some(f) = self.func_target {
            if f == f_name {
                return true;
            }
        }
        for exclude in &self.func_exclude {
            if let Some(pat) = exclude.strip_suffix('*') {
                if f_name.ends_with(pat) {
                    return false;
                }
            } else if f_name == exclude {
                return false;
            }
        }
        for include in &self.func_include {
            if let Some(pat) = include.strip_suffix('*') {
                if f_name.starts_with(pat) {
                    return true;
                }
            } else if f_name == include {
                return true;
            }
        }
        false
    }

    /// Set function pattern for `match_func`
    /// if can read from command line `--func-pattern`, or entries in file defined by `--custom-rule`
    pub fn set_func_pattern(&mut self) -> eyre::Result<()> {
        // set by `--custom-rule`
        // e.g
        // func_target xx
        // func_exclude bad_one
        // func_include test_*
        if let Some(f) = &self.custom_rules {
            let buf = std::fs::read(f).context("the path to custom rules is wrong")?;
            for line in buf.lines() {
                let line = line.context("fail to read rule line")?;
                if let Some(next) = line.strip_prefix("func_target") {
                    let f_name = next.trim();
                    self.set_func_target(f_name)?;
                }
                if let Some(next) = line.strip_prefix("func_exclude") {
                    for f in next.split(',') {
                        self.func_exclude.push(f.trim().to_string());
                    }
                }
                if let Some(next) = line.strip_prefix("func_include") {
                    for f in next.split(',') {
                        self.func_include.push(f.trim().to_string());
                    }
                }
                if let Some(next) = line.strip_prefix("func_key") {
                    for f in next.split(',') {
                        self.func_key.push(f.trim().to_string());
                    }
                }
            }
        }
        // set by `--func-pattern`
        // e.g. @test_target, !exclude_func, ?key_func, test_*, other_*
        if let Some(patterns) = self.func_pattern.take() {
            for pattern in patterns.split(',') {
                let pattern = pattern.trim();
                if let Some(pat) = pattern.strip_prefix('@') {
                    let f_name = pat.trim();
                    self.set_func_target(f_name)?;
                } else if let Some(pat) = pattern.strip_prefix('!') {
                    self.func_exclude.push(pat.to_string());
                } else if let Some(pat) = pattern.strip_prefix('?') {
                    self.func_key.push(pat.to_string())
                } else if !pattern.is_empty() {
                    self.func_include.push(pattern.to_string());
                }
            }
        }
        // read from output/func_list as default
        if self.func_include.is_empty() && self.func_target.is_none() {
            let f = output_file_path("func_list");
            if f.is_file() {
                let buf = std::fs::read(f).context("the path to custom rules is wrong")?;
                for line in buf.lines() {
                    let line = line.context("fail to read rule line")?;
                    self.func_include.push(line.trim().to_string());
                }
            } else {
                eyre::bail!(
                    "You should specific API list by either --func-pattern or --custom-rule !"
                );
            }
        }
        Ok(())
    }

    pub fn set_func_target(&mut self, f_name: &str) -> eyre::Result<()> {
        let fg = crate::global_gadgets::get_instance()
            .get_func_gadget(f_name)
            .with_context(|| format!("function name `{f_name}` is not in gagdget"))?;
        self.func_target = Some(fg.f_name);
        Ok(())
    }
}

/// Strategy for select seed
#[derive(Parser, Debug, Copy, Clone, ValueEnum)]
pub enum SelectType {
    /// Round robin
    Rr,
    /// Simulated annealing
    Sa,
}

impl Default for SelectType {
    fn default() -> Self {
        Self::Sa
    }
}

impl std::str::FromStr for SelectType {
    type Err = eyre::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "rr" | "RR" | "Rr" => Ok(Self::Rr),
            "sa" | "SA" | "Sa" => Ok(Self::Sa),
            _ => Err(eyre::eyre!("fail to parse select type")),
        }
    }
}

/// Const function for get task env
const fn task_env_var() -> &'static str {
    if let Some(v) = option_env!("HOPPER_TASK") {
        v
    } else {
        "test"
    }
}

/// Const function for get out_dir env
const fn out_dir_env_var() -> &'static str {
    if let Some(v) = option_env!("HOPPER_OUT_DIR") {
        v
    } else {
        "./"
    }
}

const fn enable_fn_pointer() -> bool {
    option_env!("HOPPER_DISABLE_FN_POINTER").is_none()
}

const fn fn_pointer_name_prefix() -> &'static str {
    if let Some(v) = option_env!("HOPPER_FUNCTION_POINTER_PREFIX") {
        v
    } else {
        "GENERATED_hopper_callback_"
    }
}

/// Const function for get map_size_pow2
const fn map_size_pow2_var() -> usize {
    if let Some(v) = option_env!("HOPPER_MAP_SIZE_POW2") {
        if v.len() == 2 {
            let bytes = v.as_bytes();
            if bytes[0] == b'1' && bytes[1] == b'7' {
                return 17;
            }
            if bytes[0] == b'1' && bytes[1] == b'8' {
                return 18;
            }
            if bytes[0] == b'1' && bytes[1] == b'9' {
                return 19;
            }
            if bytes[0] == b'2' && bytes[1] == b'0' {
                return 20;
            }
        }
    }
    16
}

/// use canary
const fn use_canary() -> bool {
    cfg!(feature = "e9_mode")
}

/// Get file path in output dir
pub fn output_file_path(file: &str) -> std::path::PathBuf {
    let path = std::path::PathBuf::from(OUTPUT_DIR);
    path.join(file)
}

/// Crate the direcotry if it does not exist
pub fn create_dir_in_output_if_not_exist(dir_name: &str) -> eyre::Result<()> {
    let dir = output_file_path(dir_name);
    if !dir.exists() {
        std::fs::create_dir(&dir)?;
    }
    Ok(())
}

/// Get constraint path in output dir
pub fn constraint_file_path() -> std::path::PathBuf {
    output_file_path(CONSTRAINT_CONFIG)
}

/// Get path in tmp directory
/// fuzzer&harness is always run at `output`'s directory in shell
pub fn tmp_file_path(file: &str) -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(crate::config::OUTPUT_DIR);
    path.push(crate::config::TMP_DIR);
    path.push(file);
    path
}

/// Set AOI_SENSITIVE_CALL accoring to environment variables.
pub static API_INSENSITIVE_COV: &str = "HOPPER_API_INSENSITIVE_COV";
pub fn get_api_sensitive_cov() -> bool {
    pub static API_SENSITIVE_COV: OnceCell<bool> = OnceCell::new();
    *API_SENSITIVE_COV
        .get_or_init(|| !matches!(std::env::var("HOPPER_API_INSENSITIVE_COV"), Ok(..)))
}

/// Enable generate failed target or not after pilot
pub fn enable_gen_fail() -> bool {
    pub static ENABLE_GEN_FAIL: OnceCell<bool> = OnceCell::new();
    *ENABLE_GEN_FAIL.get_or_init(|| !matches!(std::env::var("DISABLE_GEN_FAIL"), Ok(..)))
}

/// Get fast execute loop number
pub static FAST_EXECUTE_LOOP: &str = "HOPPER_FAST_EXECUTE_LOOP";
pub fn get_fast_execute_loop() -> usize {
    pub static ENABLE_FAST: OnceCell<usize> = OnceCell::new();
    *ENABLE_FAST.get_or_init(|| std::env::var(FAST_EXECUTE_LOOP).map_or(10, |s| s.parse().unwrap()))
}
