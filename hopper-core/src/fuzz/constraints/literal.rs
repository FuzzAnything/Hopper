//! Literal meanings for function names, arguemnt names ..
//!
//! Literal inference is used for extracting information for debugging and testing,
//! we do not use litaral to infer constraints by default now.

use super::*;
use crate::{runtime::*, utils};

// Enable infer constraints by literal
pub const ENABLE_LITERAL: bool = false || cfg!(test);

fn is_len_ident(ident: &str, prev_ident_holder: Option<&str>) -> bool {
    let related_ident = if let Some(prev_ident) = prev_ident_holder {
        ident.starts_with(&format!("n{prev_ident}"))
            || ident.starts_with(&format!("num{prev_ident}"))
    } else {
        false
    };
    related_ident
        || ident.ends_with("Len")
        || ident.ends_with("len")
        || ident.ends_with("length")
        || ident.ends_with("Length")
        || ident.ends_with("count")
        || ident.ends_with("Count")
        || ident.ends_with("size")
        || ident.ends_with("Size")
        || ident.ends_with("_sz")
        || ident.starts_with("num_")
}

fn is_index_ident(ident: &str) -> bool {
    ident.ends_with("idx")
        || ident.ends_with("index")
        || ident.ends_with("Index")
        || ident.ends_with("which")
        || ident.ends_with("offset")
        || ident.ends_with("pos")
}

fn is_file_name(ident: &str) -> bool {
    ident.ends_with("file_name")
        || ident.ends_with("filename")
        || ident.ends_with("FileName")
        || ident.ends_with("Filename")
        || ident.ends_with("file")
        || ident.ends_with("f_name")
        || ident.ends_with("fname")
}

fn function_may_save_file(f_name: &str) -> bool {
    f_name.contains("Write")
        || f_name.contains("write")
        || f_name.contains("Save")
        || f_name.contains("save")
}

pub fn is_init_function_by_name(f_name: &str) -> bool {
    f_name.contains("init")
        || f_name.contains("Init")
        || f_name.contains("create")
        || f_name.contains("Create")
        || f_name.contains("open")
        || f_name.contains("Open")
}

fn is_dealloc_function(f_name: &str) -> bool {
    f_name.contains("close")
        || f_name.contains("Close")
        || f_name.contains("free")
        || f_name.contains("Free")
        || f_name.contains("delete")
        || f_name.contains("Delete")
        || f_name.contains("destroy")
        || f_name.contains("Destroy")
}

pub fn is_backtracing_field(field_name: &str) -> bool {
    field_name.contains("parent") || field_name == "pre" || field_name.starts_with("prev")
}

pub fn infer_func_by_literal(fc: &mut FuncConstraint, f_name: &str) -> eyre::Result<()> {
    #[cfg(not(test))]
    if !crate::config::ENABLE_REFINE || !ENABLE_LITERAL {
        return Ok(());
    }
    let fg = global_gadgets::get_instance().get_func_gadget(f_name)?;
    if is_dealloc_function(fg.f_name) {
        fc.role.free_arg = true;
    }
    if is_init_function_by_name(fg.f_name) {
        fc.role.init_arg = true;
    }
    let mut prev_ptr = false;
    let mut prev_ident = None;
    for (i, &ident) in fg.arg_idents.iter().enumerate() {
        let arg_type_name = fg.arg_types[i];
        if is_file_name(ident) {
            let (is_buf, _) = utils::is_c_str_type(arg_type_name);
            if is_buf {
                let may_read = !function_may_save_file(f_name);
                let c = Constraint::File { read: may_read, is_fd: false };
                let ret = fc.set_arg_constraint(f_name, i, c);
                if let Some(c) = &ret {
                    log_new_constraint(&format!("{c:?}, literal infer func arg is file"));
                }
            }
        }

        if utils::is_primitive_type(arg_type_name) {
            let is_len = is_len_ident(ident, prev_ident);
            let is_index = is_index_ident(ident);
            if is_len || is_index {
                let c = if prev_ptr {
                    if is_len {
                        Constraint::should_be(IrEntry::arg_length(i - 1))
                    } else {
                        Constraint::less_than(IrEntry::arg_length(i - 1))
                    }
                } else {
                    Constraint::resource_related()
                };
                let ret = fc.set_arg_constraint(f_name, i, c);
                if let Some(c) = &ret {
                    log_new_constraint(&format!("{c:?}, literal infer func arg is len/index"));
                }
            }
        }
        prev_ptr = utils::is_pointer_type(arg_type_name);
        prev_ident = Some(ident);
    }
    Ok(())
}

pub fn infer_type_by_literal(tc: &mut TypeConstraint, type_name: &str) -> eyre::Result<()> {
    #[cfg(not(test))]
    if !crate::config::ENABLE_REFINE || !ENABLE_LITERAL {
        return Ok(());
    }
    if !utils::is_custom_type(type_name) || utils::is_opaque_type(type_name) {
        return Ok(());
    }
    let type_name = utils::get_static_ty(type_name);
    crate::log!(info, "literal infer type `{}`..", type_name);
    let mut prev_ptr: Option<FieldKey> = None;
    let mut prev_ident: Option<&str> = None;
    let mut state = ObjectState::root("infer", type_name);
    let builder = global_gadgets::get_instance().get_object_builder(type_name)?;
    let value = builder.generate_new(&mut state)?;
    let mut layout = value.get_layout(true);
    let num_fields = layout.fields.len();
    if num_fields > 1 {
        // to infer fields that use length first, e.g. { len, buf }
        if num_fields == 2 {
            if let Some(sub_layout) = layout.fields.first() {
                if let FieldKey::Field(_) = &sub_layout.key {
                    if utils::is_index_or_length_number(sub_layout.type_name) {
                        layout.fields.reverse();
                    }
                }
            }
        }
        for sub_layout in layout.fields.iter() {
            if let FieldKey::Field(f) = &sub_layout.key {
                if utils::is_index_or_length_number(sub_layout.type_name) {
                    let is_len = is_len_ident(f, prev_ident);
                    let is_index = is_index_ident(f);
                    if is_len || is_index {
                        let index_field = &sub_layout.key;
                        let c = if let Some(ptr_f) = &prev_ptr {
                            let ptr_field = ptr_f.clone();
                            if is_len {
                                Constraint::should_be(IrEntry::field_length(ptr_field))
                            } else {
                                Constraint::less_than(IrEntry::field_length(ptr_field))
                            }
                        } else {
                            Constraint::resource_related()
                        };
                        let mut fields = LocFields::default();
                        fields.push(index_field.clone());
                        let comment = format!("type: {type_name}, fields: {fields:?}, c: {c:?}, literal infer type is len/index");
                        if tc.set_constraint(fields, c) {
                            log_new_constraint(&comment);
                        }
                    }
                }
                if utils::is_pointer_type(sub_layout.type_name) {
                    prev_ptr = Some(sub_layout.key.clone());
                    prev_ident = Some(f);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn test_literal() {
    println!("gadgets: {:?}", global_gadgets::get_instance());
    let target = "test_arr";
    let fg = global_gadgets::get_instance().get_func_gadget(target);
    println!("fg: {fg:?}");
    CONSTRAINTS.with(|c| {
        let mut c = c.borrow_mut();
        c.init_func_constraint(target).unwrap();
        let f_constraint = c.get_func_constraint(target).unwrap();
        assert_eq!(
            f_constraint.arg_constraints[1].list[0].constraint,
            Constraint::should_be(IrEntry::arg_length(0))
        );
    });

    let type_name = "hopper::test::ArrayWrap";
    CONSTRAINTS.with(|c| {
        let mut c = c.borrow_mut();
        let tc = c.get_type_constraint_mut(type_name);
        assert_eq!(
            tc.list[0].key,
            LocFields::new(vec![FieldKey::Field("len".to_string())])
        );
        assert_eq!(
            tc.list[0].constraint,
            Constraint::should_be(IrEntry::field_length(FieldKey::Field("p".to_string())))
        );
    });
}
