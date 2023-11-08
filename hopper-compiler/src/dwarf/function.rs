use super::{ArgType, Position};

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub ret_type: ArgType,
    pub arg_types: Vec<ArgType>,
    pub external: bool,
    pub position: Position,
}

impl Function {}
