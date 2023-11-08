//! Mutate File statement

use super::*;

impl WeightedItem for FileStmt {}

impl StmtMutate for FileStmt {}

impl FileStmt {
    pub fn generate_new(
        program: &mut FuzzProgram,
        ident: &str,
        is_mut: bool,
        is_fd: bool,
        may_read: bool,
        depth: usize,
    ) -> eyre::Result<FileStmt> {
        let mut file_stmt = FileStmt::new(ident, is_mut, is_fd);
        if may_read {
            let _tmp = flag::ReuseStmtGuard::temp_disable();
            let load = LoadStmt::generate_vec( program, "u8", "file_buf", depth)?;
            let index = program.insert_or_append_stmt(load)?;
            file_stmt.set_buf_index(index);
        }
        Ok(file_stmt)
    }
}

/// Just some code to make FileFd to be Fuzzable
impl ObjGenerate for FileFd {
    fn generate_new(_state: &mut ObjectState) -> eyre::Result<Self> {
        Ok(Default::default())
    }
}

impl ObjMutate for FileFd {
    fn mutate(&mut self, _state: &mut ObjectState) -> eyre::Result<MutateOperator> {
        Ok(MutateOperator::nop())
    }

    fn mutate_by_op(
        &mut self,
        _state: &mut ObjectState,
        _keys: &[FieldKey],
        _op: &MutateOperation,
    ) -> eyre::Result<()> {
        Ok(())
    }
}