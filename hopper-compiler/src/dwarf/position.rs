#[derive(Debug, Clone)]
pub struct Position {
    // TODO: support file name
    // https://github.com/eliben/pyelftools/issues/250
    pub file: usize,
    pub line: usize,
    pub column: usize,
}
