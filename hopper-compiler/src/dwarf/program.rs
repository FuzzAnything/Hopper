use std::collections::BTreeMap;

use super::*;

#[derive(Debug, Clone)]
pub struct Program {
    pub units: Vec<ProgramUnit>,
}

#[derive(Debug, Clone)]
pub struct ProgramUnit {
    pub name: String,
    pub producer: String,
    pub type_table: BTreeMap<u64, ArgType>,
    pub fn_list: Vec<Function>,
    pub var_list: Vec<Variable>,
}
