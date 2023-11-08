use std::str::FromStr;

use clap::{ValueEnum, Parser};

#[derive(Parser, Debug, Copy, Clone, ValueEnum)]
pub enum InstrumentType {
    E9,
    Llvm,
    Cov,
}

/// Hopper - fuzz libraries fully automatically
#[derive(Parser, Debug)]
#[clap(name = "hopper-compiler")]
#[clap(version = "1.0.0", author = "Tencent")]
pub struct Config {
    /// Path of target dynamic library
    #[clap(long, value_parser, num_args(1..))]
    pub library: Vec<String>,

    /// Path of header file of library
    #[clap(long, value_parser, num_args(1..))]
    pub header: Vec<String>,

    /// Output directory of harness
    #[clap(long, value_parser, default_value = "./")]
    pub output: String,

    /// Intrument type
    #[clap(long, value_enum, value_parser, default_value = "e9")]
    pub instrument: InstrumentType,

    /// Show detailed compiling information or not
    #[clap(long, value_parser)]
    pub quiet: bool,
}

impl FromStr for InstrumentType {
    type Err = eyre::Error;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "e9" => Ok(Self::E9),
            "llvm" => Ok(Self::Llvm),
            "cov" => Ok(Self::Cov),
            _ => Err(eyre::eyre!("fail to parse instrument type")),
        }
    }
}

impl InstrumentType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::E9 => "e9",
            Self::Llvm => "llvm",
            Self::Cov => "cov",
        }
    }
}
