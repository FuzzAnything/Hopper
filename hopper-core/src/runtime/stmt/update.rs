//! Update statement
//! Update object that retuan from function calls

use super::*;
use crate::runtime::*;

/// Update: dst <= src
#[derive(Debug)]
pub struct UpdateStmt {
    /// statement which we used for update
    pub src: StmtIndex,
    /// the target we will update
    pub dst: WeakLocation,
}

impl UpdateStmt {
    pub fn new(src: StmtIndex, dst: WeakLocation) -> Self {
        Self { src, dst }
    }
}

impl StmtView for UpdateStmt {
    const KEYWORD: &'static str = "update";

    fn eval(
        &mut self,
        used_stmts: &mut [IndexedStmt],
        _resource_states: &mut ResourceStates,
    ) -> eyre::Result<()> {
        let (used_stmts, rest) = used_stmts.split_at_mut(self.src.get());
        let dst_i = self.dst.get_index()?.get();
        match &mut used_stmts[dst_i].stmt {
            FuzzStmt::Call(dst_call) => {
                if let Some(call_ret) = &mut dst_call.ret {
                    if let FuzzStmt::Load(src_load) = &mut rest[0].stmt {
                        self.fill_update_pointer(src_load, call_ret)?;
                    }
                }
            }
            FuzzStmt::Load(load_stmt) => {
                if let Some(src_value) = rest[0].stmt.get_value() {
                    let val = *u64::cast_from(src_value);
                    let op = crate::MutateOperation::IntSet { val: val.into() };
                    load_stmt.value.mutate_by_op(
                        &mut load_stmt.state,
                        self.dst.fields.as_slice(),
                        &op,
                    )?;
                }
            }
            _ => {
                crate::log!(warn, "can not update : {:?}", self);
            }
        }
        Ok(())
    }
}

impl UpdateStmt {
    /// update call ret's pointer from load statement
    fn fill_update_pointer(
        &mut self,
        src_load: &mut LoadStmt,
        call_ret: &FuzzObject,
    ) -> eyre::Result<()> {
        let src_ptr = src_load.value.get_ptr_by_keys(&[])?;
        fill_stub_pointer(
            &mut src_load.value,
            &src_load.state,
            call_ret,
            self.dst.fields.as_slice(),
        )?;
        let (_, dst_fields) = self
            .dst
            .fields
            .as_slice()
            .split_last()
            .ok_or_else(|| eyre::eyre!("remove last (Fieldkey::Pointer)"))?;
        if let Ok(dst_ptr) = call_ret.get_ptr_by_keys(dst_fields) {
            let dst_ptr = dst_ptr as *mut *mut u8;
            crate::log!(
                trace,
                "update ({}) value in loc {:?} as : {:?}",
                self.serialize()?,
                dst_ptr,
                src_ptr
            );
            unsafe { *dst_ptr = src_ptr };
            return Ok(());
        }
        Ok(())
    }
}

/// Fill pointer with stub flag, which used in load object clone from call's return irs
fn fill_stub_pointer(
    load_obj: &mut FuzzObject,
    state: &ObjectState,
    call_ret: &FuzzObject,
    prefix: &[FieldKey],
) -> eyre::Result<()> {
    if let Some(ps) = &state.pointer {
        if ps.stub {
            let mut sub_fields = state.get_location_fields().list;
            crate::log!(trace, "fill stub: {:?}, prefix: {:?}", sub_fields, prefix);
            let dst_ptr = load_obj.get_ptr_by_keys(sub_fields.as_slice())? as *mut *mut u8;
            // crate::log!(trace, "dst_ptr: {:?}", dst_ptr);
            let mut fields = prefix.to_vec();
            fields.append(&mut sub_fields);
            fields.push(FieldKey::Pointer);
            let src_ptr = call_ret.get_ptr_by_keys(fields.as_slice())?;
            // crate::log!(trace, "src_ptr: {:?}", src_ptr);
            unsafe { *dst_ptr = src_ptr };
        }
    }
    for st in &state.children {
        fill_stub_pointer(load_obj, st, call_ret, prefix)?;
    }
    Ok(())
}

impl CloneProgram for UpdateStmt {
    fn clone_with_program(&self, program: &mut FuzzProgram) -> Self {
        let src = self.src.clone_with_program(program);
        let dst = self.dst.clone_with_program(program);
        Self::new(src, dst)
    }
}

impl From<UpdateStmt> for FuzzStmt {
    fn from(stmt: UpdateStmt) -> Self {
        FuzzStmt::Update(Box::new(stmt))
    }
}

impl Serialize for UpdateStmt {
    fn serialize(&self) -> eyre::Result<String> {
        Ok(format!(
            "{} {} <= {}",
            Self::KEYWORD,
            self.dst.serialize()?,
            self.src.serialize()?
        ))
    }
}

impl Deserialize for UpdateStmt {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        // de.strip_token(Self::KEYWORD);
        let dst = WeakLocation::deserialize(de)?;
        de.eat_token("<=")?;
        let src = StmtIndex::deserialize(de)?;
        Ok(Self::new(src, dst))
    }
}

#[test]
fn test_update_eval() {
    use crate::test;
    let mut program = FuzzProgram::default();
    let call = test::generate_call_stmt("create_test_ptr");
    let call_i = program.append_stmt(call);
    let load_arr = test::generate_load_stmt::<Vec<u8>>("test", "");
    let load_ptr = load_arr.value.get_ptr_by_keys(&[]).unwrap();
    let load_arr_i = program.append_stmt(load_arr);
    let arr_dst_fields = LocFields::new(vec![
        FieldKey::Pointer,
        FieldKey::Field("p".to_string()),
        FieldKey::Pointer,
    ]);
    let arr_dst_loc = Location::new(call_i.use_index(), arr_dst_fields);
    let update_arr = UpdateStmt::new(load_arr_i.use_index(), arr_dst_loc.to_weak_loc());
    let _update_arr_i = program.append_stmt(update_arr);
    let mut load_test = test::generate_load_stmt::<Vec<test::TestType>>("test", "");
    let sub_keys = vec![FieldKey::Index(0), FieldKey::Field("p".to_string())];
    let sub_state = load_test.state.get_child_mut_by_fields(&sub_keys).unwrap();
    if let Some(ps) = sub_state.pointer.as_mut() {
        ps.stub = true;
    }
    let load_test_i = program.append_stmt(load_test);
    let test_dst_fields = LocFields::new(vec![FieldKey::Pointer]);
    let test_dst_loc = Location::new(call_i.use_index(), test_dst_fields);
    let update_test = UpdateStmt::new(load_test_i.use_index(), test_dst_loc.to_weak_loc());
    let _update_test_i = program.append_stmt(update_test);
    println!("program: {}", program.serialize().unwrap());
    program.eval().unwrap();
    assert_eq!(
        call_i
            .get_stmt_value(&program.stmts)
            .unwrap()
            .get_ptr_by_keys(arr_dst_loc.fields.as_slice())
            .unwrap(),
        load_ptr
    );
}
