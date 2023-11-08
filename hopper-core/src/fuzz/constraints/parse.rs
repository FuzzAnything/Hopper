use super::*;
use crate::{config, utils, Deserialize, FieldKey, Serialize};
use eyre::{Context, ContextCompat};
use std::fmt::Write as _;
use std::io::{BufRead, Write};
use std::path::Path;

impl Constraints {
    /// Save constraints to file
    pub fn save_to_file(&self, path: &Path) -> eyre::Result<()> {
        let mut buf = String::new();
        for (f, constraint) in self.func_constraints.iter() {
            let _ = writeln!(buf, "func {} = {}", f, constraint.serialize()?);
        }
        for (t, constraint) in self.type_constraints.iter() {
            let _ = writeln!(buf, "type {} = {}", t, constraint.serialize()?);
        }
        if !buf.is_empty() {
            let mut f = std::fs::File::create(path)?;
            crate::log!(info, "write constraints to file : {:?}", path);
            f.write_all(buf.as_bytes())?;
            f.flush()?;
        }
        Ok(())
    }

    /// Read constraints from file
    pub fn read_from_config(&mut self, path: &Path) -> eyre::Result<()> {
        let buf = std::fs::read(path)?;
        for line in buf.lines() {
            let line = line.context("fail to read config line")?;
            let mut de = crate::Deserializer::new(&line, None);
            let ty = de.next_token_until(" ")?;
            match ty {
                "func" => {
                    let f = de.next_token_until(" ")?;
                    de.eat_token("=")?;
                    let constraint = FuncConstraint::deserialize(&mut de)?;
                    self.func_constraints.insert(f.to_string(), constraint);
                }
                "type" => {
                    let t = de.next_token_until(" ")?;
                    de.eat_token("=")?;
                    let constraint = TypeConstraint::deserialize(&mut de)?;
                    self.type_constraints.insert(t.to_string(), constraint);
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Read internal config
    pub fn read_internal_config(&mut self) -> eyre::Result<()> {
        let buf = include_bytes!("internal.rule");
        let mut func_internal = vec![];
        for line in buf.lines() {
            let line = line.context("fail to read rule line")?;
            if let Some(next) = line.strip_prefix("func_internal") {
                for f in next.split(',') {
                    func_internal.push(f.trim().to_string());
                }
            }
        }
        // internal functions: do not need for inference
        for (f_name, _f) in global_gadgets::get_instance().functions.iter() {
            if func_internal.contains(f_name) {
                crate::log!(info, "load internal func: {f_name}");
                self.init_func_constraint(f_name)?;
                let fc = self.get_func_constraint_mut(f_name)?;
                fc.internal = true;
                fc.can_succeed = true;
            }
        }
        self.read_from_custom_buf(buf)?;
        Ok(())
    }

    /// Read constraint rules from custom file
    pub fn read_from_custom(&mut self) -> eyre::Result<()> {
        let default_path = config::output_file_path("misc/custom_rule");
        if let Some(f) = &config::get_config().custom_rules {
            let buf = std::fs::read(f).context("the path to custom rules is wrong")?;
            self.read_from_custom_buf(&buf)?;
            std::fs::copy(f, default_path)?;
        } else if default_path.is_file() {
            let buf = std::fs::read(default_path).context("the path to custom rules is wrong")?;
            self.read_from_custom_buf(&buf)?;
        }
        Ok(())
    }

    fn read_from_custom_buf(&mut self, buf: &[u8]) -> eyre::Result<()> {
        let mut need_build_graph = false;
        for line in buf.lines() {
            let line = line.context("fail to read rule line")?;
            crate::log!(trace, "custom line: {line}");
            let mut de = crate::Deserializer::new(&line, None);
            if de.peek_char().is_none() {
                continue;
            }
            let ty = de.next_token_until(" ")?.trim();
            match ty {
                "alias" => {
                    let alias_name = de.next_token_until("<-")?.trim();
                    let alias_name = utils::get_static_ty(alias_name);
                    need_build_graph = true;
                    loop {
                        de.trim_start();
                        let f_name = de.next_token_until("[")?;
                        let fg = global_gadgets::get_mut_instance()
                            .functions
                            .get_mut(f_name)
                            .with_context(|| format!("function {f_name} is not exited"))?;
                        de.eat_token("$")?;
                        if de.strip_token("ret") {
                            fg.alias_ret_type = Some(alias_name);
                        } else {
                            let arg_i: usize = de.parse_number()?;
                            // pointer
                            let arg_alias_type = if de.strip_token("*") {
                                let is_mut = utils::is_mut_pointer_type(fg.arg_types[arg_i]);
                                if is_mut {
                                    utils::get_static_ty(&utils::mut_pointer_type(alias_name))
                                } else {
                                    utils::get_static_ty(&utils::const_pointer_type(alias_name))
                                }
                            } else {
                                alias_name
                            };
                            fg.alias_arg_types[arg_i] = arg_alias_type;
                        }
                        crate::log!(info, "update alias: {:?}", fg);
                        de.eat_token("]")?;
                        de.trim_start();
                        if !de.strip_token(",") {
                            break;
                        }
                    }
                }
                "ctx" => {
                    let f_name = de.next_token_until("[")?;
                    if self.get_func_constraint(f_name).is_none() {
                        continue;
                    }
                    let ctx = CallContext::from_rule(&mut de)?;
                    self.add_func_context(f_name, ctx)?;
                }
                "func" => {
                    let sig_list = parse_func_constraint(&mut de)?;
                    for sig in sig_list {
                        #[cfg(not(test))]
                        if !crate::config::get_config().match_func(&sig.f_name)
                            && self.get_func_constraint(&sig.f_name).is_none()
                        {
                            continue;
                        }
                        if let Ok(fc) = self.get_func_constraint_mut(&sig.f_name) {
                            fc.set_constraint(&sig.f_name, sig.arg_pos, sig.fields, sig.constraint);
                        }
                    }
                }
                "type" => {
                    let (type_name, fields, is_pointer) = parse_type_lvalue(&mut de)?;
                    de.trim_start();
                    if de.strip_token("$opaque") {
                        crate::log!(info, "add `{}` as opaque type", type_name);
                        global_gadgets::get_mut_instance().add_opaque_type(&type_name);
                        continue;
                    }
                    let c: Constraint = Constraint::from_rule(&mut de)?;
                    de.trim_start();
                    if de.strip_token("<-") {
                        crate::log!(warn, "Invalid custom constraint, <- is not support now");
                    } else if is_pointer {
                        let const_ty = utils::const_pointer_type(&type_name);
                        self.add_type_constraint(&const_ty, fields.clone(), c.clone());
                        let mut_ty = utils::mut_pointer_type(&type_name);
                        self.add_type_constraint(&mut_ty, fields, c);
                    } else {
                        self.add_type_constraint(&type_name, fields, c);
                    }
                }
                "assert" => {
                    let assertion = crate::fuzz::stmt::parse_assertion(&mut de)?;
                    if self.get_func_constraint(&assertion.f_name).is_none() {
                        continue;
                    }
                    crate::fuzz::stmt::add_assertion(assertion);
                }
                _ => {}
            }
        }
        if need_build_graph {
            global_gadgets::get_mut_instance().build_arg_and_ret_graph();
        }
        Ok(())
    }
}

impl Constraint {
    pub fn from_rule(de: &mut crate::Deserializer) -> eyre::Result<Self> {
        if de.strip_token("$null") {
            return Ok(Self::SetNull);
        }
        if de.strip_token("$non_null") {
            return Ok(Self::NonNull);
        }
        if de.strip_token("$need_init") {
            return Ok(Self::NeedInit);
        }
        if de.strip_token("$non_zero") {
            return Ok(Self::NonZero);
        }
        if de.strip_token("$write_file") {
            return Ok(Self::File {
                read: false,
                is_fd: false,
            });
        }
        if de.strip_token("$write_fd") {
            return Ok(Self::File {
                read: false,
                is_fd: true,
            });
        }
        if de.strip_token("$read_file") {
            return Ok(Self::File {
                read: true,
                is_fd: false,
            });
        }
        if de.strip_token("$read_fd") {
            return Ok(Self::File {
                read: true,
                is_fd: true,
            });
        }
        if de.strip_token("$ret_from") {
            de.eat_token("(")?;
            let f_name = de.next_token_until(")")?.to_string();
            return Ok(Self::RetFrom { ret_f: f_name });
        }
        if de.strip_token("$cast_from") {
            de.eat_token("(")?;
            let type_name = de.next_token_until(")")?;
            let cast_type = if let Some(inner) = type_name.strip_prefix("*mut") {
                utils::mut_pointer_type(&convert_type(inner.trim()))
            } else if let Some(inner) = type_name.strip_prefix("*const") {
                utils::const_pointer_type(&convert_type(inner.trim()))
            } else {
                convert_type(type_name)
            };
            return Ok(Self::CastFrom { cast_type });
        }
        if de.strip_token("$range") {
            de.eat_token("(")?;
            let min = IrEntry::from_rule(de)?;
            de.eat_token(",")?;
            let max = IrEntry::from_rule(de)?;
            de.eat_token(")")?;
            return Ok(Self::Range { min, max });
        }
        if de.strip_token("$lt") {
            de.eat_token("(")?;
            let max = IrEntry::from_rule(de)?;
            de.eat_token(")")?;
            return Ok(Self::Range { min: 0.into(), max });
        }
        if de.strip_token("$use") {
            de.eat_token("(")?;
            let member = de.next_token_until(")")?.to_string();
            return Ok(Self::UseUnionMember { member });
        }
        if de.strip_token("$arr_len") {
            de.eat_token("(")?;
            let ir_member = IrEntry::from_rule(de)?;
            de.eat_token(")")?;
            if let IrEntry::Constant(len) = ir_member {
                return Ok(Self::ArrayLength {
                    len: len.try_into().unwrap(),
                });
            } else {
                return Err(eyre::eyre!("Expect a length here."));
            }
        }
        if de.strip_token("$init_with") {
            de.eat_token("(")?;
            let f_name = de.next_token_until(",")?.to_string();
            de.trim_start();
            let arg_pos = de.parse_number()?;
            de.eat_token(")")?;
            return Ok(Self::InitWith { f_name, arg_pos });
        }
        let val = IrEntry::from_rule(de)?;
        Ok(Self::SetVal { val })
    }
}

fn convert_type(ty: &str) -> String {
    if !utils::is_primitive_type(ty) && !ty.starts_with("hopper") {
        // all type in harness should starts with hopper_harness
        format!("hopper_harness::{ty}")
    } else {
        ty.to_string()
    }
}

pub fn parse_type_lvalue(de: &mut crate::Deserializer) -> eyre::Result<(String, LocFields, bool)> {
    let mut left = de.next_token_until("=")?.trim();
    let mut is_pointer = false;
    if let Some(s) = left.strip_suffix('*') {
        left = s.trim();
        is_pointer = true;
    }
    let mut fields = LocFields::default();
    let type_name = if let Some(pos) = left.find('[') {
        let (type_name, field) = left.split_at(pos);
        let field = field.trim_start_matches('[').trim_end_matches(']');
        let field = if field == "$" {
            FieldKey::union_root()
        } else {
            field.to_string().into()
        };
        fields.push(field);
        type_name
    } else {
        left
    };
    Ok((convert_type(type_name), fields, is_pointer))
}

pub fn parse_func_constraint(de: &mut crate::Deserializer) -> eyre::Result<Vec<ConstraintSig>> {
    let mut f_name = de.next_token_until("[")?;
    if f_name == "@" {
        if let Some(target) = crate::config::get_config().func_target {
            f_name = target;
        }
    }
    de.eat_token("$")?;
    let key_arg_pos: usize = de.parse_number()?;
    de.eat_token("]")?;
    let key_fields = if de.peek_char() == Some('[') {
        LocFields::deserialize(de)?
    } else {
        LocFields::default()
    };
    de.eat_token("=")?;
    de.trim_start();
    let mut list = parse_len_factors(de, f_name, key_arg_pos, &key_fields)?;
    if list.is_empty() {
        let c: Constraint = Constraint::from_rule(de)?;
        list.push(ConstraintSig {
            f_name: f_name.to_string(),
            arg_pos: key_arg_pos,
            fields: key_fields,
            constraint: c,
        });
    }
    Ok(list)
}

fn parse_len_factors(
    de: &mut crate::Deserializer,
    f_name: &str,
    key_arg_pos: usize,
    key_fields: &LocFields,
) -> eyre::Result<Vec<ConstraintSig>> {
    let mut list = vec![];
    if !de.strip_token("$len_factors") {
        return Ok(list);
    }
    de.eat_token("(")?;
    for item in de.next_token_until(")")?.split(',') {
        let mut sub_de = crate::Deserializer::new(item, None);
        let loc: IrEntry = IrEntry::from_rule(&mut sub_de)
            .with_context(|| format!("fail to parse loc: `{item}` for len_factors"))?;
        if let IrEntry::Constant(val) = loc {
            if sub_de.strip_token("..") {
                let loc_end = IrEntry::from_rule(&mut sub_de)
                    .with_context(|| format!("fail to parse loc: `{item}` for len_factors"))?;
                if let Some((arg_pos, fields)) = loc_end.get_location_from_any() {
                    let c = Constraint::Range {
                        min: val.into(),
                        max: IrEntry::Length {
                            arg_pos: Some(key_arg_pos),
                            fields: key_fields.clone(),
                            is_factor: true,
                        },
                    };
                    list.push(ConstraintSig {
                        f_name: f_name.to_string(),
                        arg_pos: arg_pos.unwrap_or_default(),
                        fields: fields.clone(),
                        constraint: c,
                    });
                }
                continue;
            }
            let c = Constraint::LengthFactor { coef: val };
            list.push(ConstraintSig {
                f_name: f_name.to_string(),
                arg_pos: key_arg_pos,
                fields: key_fields.clone(),
                constraint: c,
            });
        } else if let Some((arg_pos, fields)) = loc.get_location_from_any() {
            let c = Constraint::SetVal {
                val: IrEntry::Length {
                    arg_pos: Some(key_arg_pos),
                    fields: key_fields.clone(),
                    is_factor: true,
                },
            };
            list.push(ConstraintSig {
                f_name: f_name.to_string(),
                arg_pos: arg_pos.unwrap_or_default(),
                fields: fields.clone(),
                constraint: c,
            });
        }
    }
    Ok(list)
}

#[test]
fn test_read_custom_rule() {
    println!("gadgets: {:?}", global_gadgets::get_instance());
    let buf = "
    func func_add[$0] = 128
    func func_add[$0] = $non_zero
    func test_arr[$1] = $len($0)
    func test_arr[$0] = $len_factors(2, $0, $1)
    func test_arr[$0] = $arr_len(256)
    func test_arr[$1] = $range(0, $len($0))
    func func_create[$0] = \"magic\"
    func test_mutate_arr[$0] = $read_file
    func test_arr[$0] = $ret_from(test_create)
    func test_arr[$0] = $cast_from(*mut u32)
    type hopper::test::ArrayWrap[len] = $len(p)
    // type hopper::test::TestType = $opaque
    type hopper::test::TestType* = $init_with(test_arr, 0)
    func func_struct[$0][index] = 10 
    func func_struct[$0][p] = $null
    func func_struct[$0][len] = $len(p)
    ctx test_arr[$0] <- test_create
    ctx test_arr[$0] <- test_create ?
    ctx test_arr[*] <- test_create
    ";
    let mut constraints = Constraints::default();
    constraints.init_func_constraint("func_add").unwrap();
    constraints.init_func_constraint("test_arr").unwrap();
    constraints.init_func_constraint("func_create").unwrap();
    constraints.init_func_constraint("test_mutate_arr").unwrap();
    constraints.init_func_constraint("func_struct").unwrap();
    constraints.read_from_custom_buf(buf.as_bytes()).unwrap();
    println!("constraints: {constraints:#?}");
}

#[test]
fn test_parse_len_factors() {
    let len_entry = IrEntry::Length {
        arg_pos: Some(3),
        fields: LocFields::default(),
        is_factor: true,
    };
    let factors = parse_len_factors(
        &mut crate::Deserializer::new("$len_factors(3, $2)", None),
        "fff",
        3,
        &LocFields::default(),
    )
    .unwrap();

    println!("factors: {factors:?}");
    assert_eq!(factors[0].constraint, Constraint::LengthFactor { coef: 3 });
    assert_eq!(factors[1].arg_pos, 2);
    assert_eq!(
        factors[1].constraint,
        Constraint::SetVal {
            val: len_entry.clone()
        }
    );
    let factors = parse_len_factors(
        &mut crate::Deserializer::new("$len_factors(3, $len($1))", None),
        "fff",
        3,
        &LocFields::default(),
    )
    .unwrap();
    assert_eq!(factors[0].constraint, Constraint::LengthFactor { coef: 3 });
    assert_eq!(factors[1].arg_pos, 1);
    assert_eq!(
        factors[1].constraint,
        Constraint::SetVal {
            val: len_entry.clone()
        }
    );
    let factors = parse_len_factors(
        &mut crate::Deserializer::new("$len_factors(3, 0..$len($1))", None),
        "fff",
        3,
        &LocFields::default(),
    )
    .unwrap();
    println!("factors: {factors:?}");
    assert_eq!(factors[0].constraint, Constraint::LengthFactor { coef: 3 });
    assert_eq!(factors[1].arg_pos, 1);
    assert_eq!(
        factors[1].constraint,
        Constraint::Range {
            min: IrEntry::Constant(0),
            max: len_entry.clone()
        }
    );
    let factors = parse_len_factors(
        &mut crate::Deserializer::new("$len_factors($1, $2)", None),
        "fff",
        3,
        &LocFields::default(),
    )
    .unwrap();
    assert_eq!(factors[0].arg_pos, 1);
    assert_eq!(
        factors[0].constraint,
        Constraint::SetVal {
            val: len_entry.clone()
        }
    );
    assert_eq!(factors[1].arg_pos, 2);
    assert_eq!(
        factors[1].constraint,
        Constraint::SetVal {
            val: len_entry.clone()
        }
    );
}
