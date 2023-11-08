use super::*;
use hopper_derive::{EnumKind, Serde};

use crate::{config, runtime::*, utils, EnumKind};

#[derive(Debug, Clone, Serde, PartialEq, Eq, EnumKind)]
pub enum Constraint {
    NonNull,
    SetNull,
    NeedInit,
    File { read: bool, is_fd: bool },
    SetVal { val: IrEntry },
    Range { min: IrEntry, max: IrEntry },
    CastFrom { cast_type: String },
    ArrayLength { len: IrEntry },
    RetFrom { ret_f: String },
    UseUnionMember { member: String },
    InitWith { f_name: String, arg_pos: usize },
    LengthFactor { coef: u64 },
    OpaqueType,
    Context { context: CallContext },
    NonZero,
    None,
}

/// Function constraint
#[derive(Debug, Default, Clone, Serde)]
pub struct FuncConstraint {
    /// can succeed with refined mutation
    pub can_succeed: bool,
    /// fail after insert it
    pub insert_fail: bool,
    /// Internal funciton
    pub internal: bool,
    /// constraints of argument
    pub arg_constraints: Vec<TypeConstraint>,
    /// group for related args
    pub arg_group: Vec<usize>,
    /// contexts
    pub contexts: Vec<CallContext>,
    // the effect caused by the function
    pub role: role::FuncRole,
    // Return's type
    pub ret: ret::RetType,
}

/// Type constraint
#[derive(Debug, Default, Clone, Serde)]
pub struct TypeConstraint {
    pub list: Vec<TypeConstraintItem>,
}

#[derive(Debug, Clone, Serde)]
pub struct TypeConstraintItem {
    pub key: LocFields,
    pub constraint: Constraint,
}

/// Signature of a constraint
#[derive(Debug, Clone)]
pub struct ConstraintSig {
    pub f_name: String,
    pub arg_pos: usize,
    pub fields: LocFields,
    pub constraint: Constraint,
}

impl Constraint {
    pub fn should_refine_first(&self) -> bool {
        matches!(self, Self::SetNull | Self::NonNull | Self::CastFrom { .. })
    }

    pub fn should_not_mutate(&self) -> bool {
        matches!(
            self,
            Self::SetNull
                | Self::SetVal { val: _ }
                | Self::File { read: _, is_fd: _ }
                | Self::RetFrom { ret_f: _ }
        )
    }

    pub fn resource_related() -> Self {
        Self::Range {
            min: 0_u64.into(),
            max: config::MAX_RANGE_NUM.into(),
        }
    }

    pub fn less_than(entry: IrEntry) -> Self {
        Self::Range {
            min: 0_u64.into(),
            max: entry,
        }
    }

    pub fn should_be(entry: IrEntry) -> Self {
        Self::SetVal { val: entry }
    }

    pub fn is_void_cast(&self) -> bool {
        if let Constraint::CastFrom { cast_type } = self {
            if cast_type == "hopper::runtime::FuzzMutPointer<i8>" {
                return true;
            }
        }
        false
    }

    pub fn get_length_loc(&self) -> Option<(usize, &LocFields)> {
        match self {
            Self::SetVal {
                val:
                    IrEntry::Length {
                        arg_pos,
                        fields,
                        is_factor: _,
                    },
            } => Some((arg_pos.unwrap_or_default(), fields)),
            Self::Range {
                min: _,
                max:
                    IrEntry::Length {
                        arg_pos,
                        fields,
                        is_factor: _,
                    },
            } => Some((arg_pos.unwrap_or_default(), fields)),
            _ => None,
        }
    }

    pub fn shrink_range(&mut self) {
        if let Self::Range {
            min: _,
            max: IrEntry::Constant(val),
        } = self
        {
            *val /= 2;
        }
    }
}

impl FuncConstraint {
    /// Init function's constraints
    pub fn init(f_name: &str) -> eyre::Result<Self> {
        let arg_types = global_gadgets::get_instance()
            .get_func_gadget(f_name)?
            .arg_types;
        let len = if utils::is_variadic_function(arg_types) {
            arg_types.len() - 1
        } else {
            arg_types.len()
        };
        let internal = f_name.starts_with(FN_POINTER_PREFIX);
        let mut fc = FuncConstraint {
            arg_constraints: vec![TypeConstraint::default(); len],
            arg_group: (0..len).collect(),
            internal,
            ..Default::default()
        };
        fc.ret.infer(f_name)?;
        literal::infer_func_by_literal(&mut fc, f_name)?;
        Ok(fc)
    }

    /// If it is successful in executing
    pub fn is_success(&self) -> bool {
        #[cfg(test)]
        return true;
        #[cfg(not(test))]
        return self.can_succeed && !self.insert_fail && !self.internal;
    }

    /// check `f_name` and `arg_pos` is forbidden context or not
    pub fn is_forbidden_ctx(&self, f_name: &str, arg_pos: Option<usize>) -> bool {
        for ctx in &self.contexts {
            if ctx.f_name == f_name && ctx.related_arg_pos == arg_pos {
                return ctx.is_forbidden();
            }
        }
        false
    }

    /// Set ith-arg 's constraint
    pub fn set_arg_constraint(
        &mut self,
        f_name: &str,
        arg_pos: usize,
        constraint: Constraint,
    ) -> Option<ConstraintSig> {
        self.set_constraint(f_name, arg_pos, LocFields::default(), constraint)
    }

    /// Set ith-arg 's constraint with key
    pub fn set_constraint(
        &mut self,
        f_name: &str,
        arg_pos: usize,
        fields: LocFields,
        constraint: Constraint,
    ) -> Option<ConstraintSig> {
        self.group_related_args(arg_pos, &constraint);
        if self.arg_constraints[arg_pos].set_constraint(fields.clone(), constraint.clone()) {
            crate::log!(
                info,
                "add constraint on function `{f_name}` 's {arg_pos}-th arg, fields: {}, constraint {constraint:?}",
                fields.serialize().unwrap()
            );
            return Some(ConstraintSig {
                f_name: f_name.to_string(),
                arg_pos,
                fields,
                constraint,
            });
        }
        crate::log!(trace, "constraint {constraint:?} exists");
        None
    }

    /// Check if the function's return can be used for arguments or fields
    /// we avoid use static and unwriteable pointers to be arguments
    #[inline]
    pub fn can_used_as_arg(&self) -> bool {
        self.can_succeed
            && !self.insert_fail
            && self.role.can_used_as_arg()
            && self.ret.can_used_as_arg()
    }

    /// Group arguments that related
    pub fn group_related_args(&mut self, arg_pos: usize, c: &Constraint) {
        match c {
            Constraint::SetVal { val } => {
                self.union_related_args(val, arg_pos);
            }
            Constraint::Range { min, max } => {
                self.union_related_args(min, arg_pos);
                self.union_related_args(max, arg_pos);
            }
            _ => {}
        }
    }

    fn union_related_args(&mut self, entry: &IrEntry, cur_i: usize) {
        if let IrEntry::Length {
            arg_pos: Some(arg_pos_inner),
            fields: _,
            is_factor: _,
        } = entry
        {
            if *arg_pos_inner != cur_i {
                self.arg_group[cur_i] = *arg_pos_inner;
            }
        }
    }

    /// Get related arguments
    pub fn get_related_args(&self, arg_pos: usize) -> Vec<usize> {
        let group = self.arg_group[arg_pos];
        let mut args = vec![];
        for (p, i) in self.arg_group.iter().enumerate() {
            if *i == group && p != arg_pos {
                args.push(p);
            }
        }
        args
    }

    pub fn is_file(&self, arg_pos: usize) -> bool {
        self.arg_constraints[arg_pos]
            .list
            .iter()
            .any(|item| matches!(item.constraint, Constraint::File { .. }))
    }
}

impl TypeConstraint {
    pub fn init(type_name: &str) -> Self {
        let mut tc = TypeConstraint::default();
        if let Err(e) = literal::infer_type_by_literal(&mut tc, type_name) {
            crate::log!(warn, "infer {type_name} error: {}", e);
        }
        tc
    }

    pub fn set_constraint(&mut self, key: LocFields, constraint: Constraint) -> bool {
        // crate::log!(trace, "set constraint: {constraint:?}");
        for item in self.list.iter_mut() {
            if item.key != key {
                continue;
            }
            // skip the same constraint
            if item.constraint == constraint {
                return false;
            }
            // merge constraint
            // choose the minimal bound
            match &constraint {
                Constraint::NonZero => {
                    if let Constraint::Range { min, max: _ } = &mut item.constraint {
                        if let IrEntry::Constant(val) = min {
                            if *val == 0 {
                                *min = 1.into();
                                return true;
                            }
                        }
                        return false;
                    }
                }
                Constraint::Range { min, max } => {
                    // if let Constraint::SetVal { val: _ } = &item.constraint {
                    // }
                    if matches!(item.constraint, Constraint::NonZero) {
                        if let IrEntry::Constant(val) = min {
                            if *val == 0 {
                                item.constraint = Constraint::Range {
                                    min: 1.into(),
                                    max: max.clone(),
                                };
                                return true;
                            }
                        }
                        return false;
                    }
                }
                _ => {}
            }
            // update constraint
            if item.constraint.kind() == constraint.kind() {
                match constraint {
                    Constraint::ArrayLength { len: new_len } => {
                        if let Constraint::ArrayLength { len } = &mut item.constraint {
                            if let IrEntry::Constant(len_val) = len {
                                if let IrEntry::Constant(new_len_val) = new_len {
                                    if new_len_val > *len_val {
                                        *len_val = new_len_val;
                                        return true;
                                    }
                                }
                            }
                            if new_len.is_length() {
                                *len = new_len;
                                return true;
                            }
                        }
                        return false;
                    }
                    Constraint::LengthFactor { coef: new_coef } => {
                        // update new one
                        if let Constraint::LengthFactor { coef } = &mut item.constraint {
                            if new_coef > *coef {
                                *coef = new_coef;
                                return true;
                            }
                        }
                        return false;
                    }
                    Constraint::File {
                        read: new_read,
                        is_fd: _,
                    } => {
                        if let Constraint::File { read, is_fd: _ } = &mut item.constraint {
                            if new_read && !*read {
                                *read = new_read;
                                return true;
                            }
                        }
                        return false;
                    }
                    Constraint::SetVal { ref val } => {
                        if let Constraint::SetVal { val: val2 } = &item.constraint {
                            if val.equal(val2) {
                                return false;
                            }
                        }
                        continue;
                    }
                    Constraint::Range { ref min, ref max } => {
                        if let Constraint::Range {
                            min: min2,
                            max: max2,
                        } = &item.constraint
                        {
                            if min.equal(min2) && max.equal(max2) {
                                return false;
                            }
                            if min.less(min2) && max.greater(max2) {
                                return false;
                            }
                        }
                        continue;
                    }
                    _ => {}
                }
                // exists
                return false;
            }
        }
        if constraint.should_not_mutate() {
            self.list.retain(|item| item.key != key);
        }
        if constraint.should_refine_first() {
            let field_len = key.len();
            let mut off = 0;
            for c in self.list.iter() {
                if !c.constraint.should_refine_first() || field_len <= c.key.len() {
                    break;
                }
                off += 1;
            }
            self.list
                .insert(off, TypeConstraintItem { key, constraint });
        } else {
            self.list.push(TypeConstraintItem { key, constraint });
        }
        true
    }
}

impl Serialize for ConstraintSig {
    fn serialize(&self) -> eyre::Result<String> {
        if self.fields.is_empty() {
            return Ok(format!(
                "{}[${}] = {}",
                self.f_name,
                self.arg_pos,
                self.constraint.serialize()?
            ));
        }
        Ok(format!(
            "{}[${}][{}] = {}",
            self.f_name,
            self.arg_pos,
            self.fields.serialize()?,
            self.constraint.serialize()?
        ))
    }
}

impl Deserialize for ConstraintSig {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self> {
        let f_name = de.parse_string()?;
        de.eat_token("[$")?;
        let arg_pos = de.parse_number()?;
        de.eat_token("]")?;
        let fields = if de.strip_token("[") {
            let loc = LocFields::deserialize(de)?;
            de.eat_token("]")?;
            loc
        } else {
            LocFields::default()
        };
        de.eat_token("= ")?;
        let constraint = constraint::Deserialize::deserialize(de)?;
        Ok(Self {
            f_name,
            arg_pos,
            fields,
            constraint,
        })
    }
}

#[test]
fn test_constraint_sig_serde() -> eyre::Result<()> {
    let constraint_sig = ConstraintSig {
        f_name: "test_constraint_sig_serde".to_owned(),
        arg_pos: 2,
        fields: LocFields::default(),
        constraint: Constraint::SetVal {
            val: IrEntry::Constant(64),
        },
    };
    let ser_str = constraint_sig.serialize()?;
    println!("{ser_str}");
    let mut de = Deserializer::new(&ser_str, None);
    let de_sig = ConstraintSig::deserialize(&mut de)?;
    assert_eq!(de_sig.f_name, "test_constraint_sig_serde");
    assert_eq!(de_sig.arg_pos, 2);
    assert_eq!(de_sig.fields, LocFields::default());
    assert_eq!(
        de_sig.constraint,
        Constraint::SetVal {
            val: IrEntry::Constant(64)
        }
    );
    Ok(())
}

#[test]
fn test_parse_sig() -> eyre::Result<()> {
    let sig = "png_malloc_default[$1] = Range${ min: Constant${ f0: 0,  },  max: Constant${ f0: 1024,  },  }, ";
    let mut de = Deserializer::new(sig, None);
    let de_sig = ConstraintSig::deserialize(&mut de)?;
    println!("{de_sig:?}");
    Ok(())
}

#[test]
fn test_insert_constraint() {
    let mut tc = TypeConstraint::default();
    let key = LocFields::new(vec![FieldKey::Index(0)]);
    let length_constraint = Constraint::SetVal {
        val: IrEntry::Length {
            arg_pos: Some(0),
            fields: LocFields::default(),
            is_factor: false,
        },
    };
    let suc = tc.set_constraint(key.clone(), length_constraint.clone());
    assert!(suc);
    let suc = tc.set_constraint(key.clone(), length_constraint.clone());
    assert!(!suc);
    let range_constraint = Constraint::Range {
        min: 0.into(),
        max: 100.into(),
    };
    let suc = tc.set_constraint(key.clone(), range_constraint.clone());
    assert!(suc);
    let small_range_constraint = Constraint::Range {
        min: 0.into(),
        max: 50.into(),
    };
    let suc = tc.set_constraint(key.clone(), small_range_constraint.clone());
    assert!(suc);
    let suc = tc.set_constraint(key.clone(), range_constraint.clone());
    assert!(!suc);


}
