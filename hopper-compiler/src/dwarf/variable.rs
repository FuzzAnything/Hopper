use super::*;

#[derive(Debug, Clone)]
pub struct Variable {
    pub name: String,
    pub ty: ArgType,
    pub external: bool,
    pub position: Position,
}

impl Variable {}
