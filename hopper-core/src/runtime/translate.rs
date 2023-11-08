use std::collections::HashSet;
use std::fmt::Write;

use super::*;
use crate::utils;
use eyre::{Context, ContextCompat};
use regex::{self, Regex};

pub trait Translate {
    fn translate_to_c(&self) -> eyre::Result<String>;
}

pub trait ObjectTranslate: ObjectSerialize {
    fn translate_obj_to_c(
        &self,
        state: &ObjectState,
        _program: &FuzzProgram,
    ) -> eyre::Result<String> {
        self.serialize_obj(state)
    }
}

static HEADER: &str = r#"#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
typedef uint8_t   u8;   
typedef uint16_t  u16;  
typedef uint32_t  u32;  
typedef uint64_t  u64;
typedef unsigned int usize;
typedef int8_t  i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef int isize;
typedef float f32;
typedef double f64;
"#;

impl Translate for FuzzProgram {
    fn translate_to_c(&self) -> eyre::Result<String> {
        // Compile the regular expression
        let callback_re =
            Regex::new(format!(r"{}([^0-9]*)(\d+)", crate::FN_POINTER_PREFIX).as_str())
                .context("failed to compile regular expression")?;
        let mut out = String::new();
        out.push_str(HEADER);
        out.push_str("int main() {\n");
        let mut callbacks = HashSet::new();
        for is in self.stmts.iter() {
            let value_name = format!("v{}", is.index.get());
            match &is.stmt {
                FuzzStmt::Load(load) => {
                    let type_name = load.value.type_name();
                    let left = get_c_left_operand(&value_name, type_name);
                    let right = load.value.translate_obj_to_c(&load.state, self)?;
                    // Use regular expression to capture all the appearance of a generated callback.
                    for caps in callback_re.captures_iter(&right) {
                        if let Some(captured) = caps.get(0) {
                            callbacks.insert(captured.as_str().to_owned());
                        }
                    }
                    let ident = load.get_ident();
                    let line = format!("    {left} = {right}; // {ident}\n");
                    // The intialization of vec before is stored in stack,
                    // we should restore it in heap.
                    if let Some(start) = find_next(type_name, "alloc::vec::Vec<") {
                        let tmp_value_name = value_name.clone() + "_tmp";
                        let line = line.replace(&value_name, &tmp_value_name);
                        out.push_str(&line);
                        let pointer_type =
                            "hopper::runtime::FuzzMutPointer<".to_string() + &type_name[start..];
                        let left = get_c_left_operand(&value_name, &pointer_type);
                        let line =
                            format!("    {} = malloc(sizeof {});\n", &left, &tmp_value_name,);
                        out.push_str(&line);
                        let line = format!(
                            "    memcpy({}, {}, sizeof {});\n",
                            &value_name, &tmp_value_name, &tmp_value_name,
                        );
                        out.push_str(&line);
                    } else {
                        out.push_str(&line);
                    }
                }
                FuzzStmt::Call(call) => {
                    let left = if let Some(ty) = call.fg.ret_type {
                        format!("{} = ", get_c_left_operand(&value_name, ty))
                    } else {
                        "".to_string()
                    };
                    let args: Vec<String> =
                        call.args.iter().map(|i| format!("v{}", i.get())).collect();
                    let line = format!(
                        "    {}{}({}); // {}\n",
                        &left,
                        call.name,
                        args.join(", "),
                        call.ident
                    );
                    out.push_str(&line);
                }
                FuzzStmt::Update(update) => {
                    let state = ObjectState::root("update", "");
                    let left = update.dst.translate_obj_to_c(&state, self)?;
                    let line = format!("    {} = v{};\n", left, update.src.get());
                    out.push_str(&line);
                }
                FuzzStmt::Assert(assert) => {
                    if let AssertRule::NonNull { stmt } = &assert.rule {
                        let line = format!("    if (v{} == NULL) return 0;\n", stmt.get());
                        out.push_str(&line);
                    }
                }
                FuzzStmt::File(file) => {
                    let line = format!(
                        "    char* path_{} = \"{}\";\n",
                        value_name,
                        file.get_file_name()
                    );
                    out.push_str(&line);
                    if let Some(i) = &file.buf_stmt {
                        let line =
                            format!("    FILE *f_{value_name} = fopen(path_{value_name}, \"wb\");\n");
                        out.push_str(&line);
                        let line = format!(
                            "    fwrite(v{}, sizeof v{}_tmp, 1, f_{});\n",
                            i.get(),
                            i.get(),
                            value_name
                        );
                        out.push_str(&line);
                        if !file.is_fd {
                            let line = format!("    fclose(f_{value_name});\n");
                            out.push_str(&line);
                        }
                    }
                    if file.is_fd {
                        let line = format!("    int {value_name} = fileno(f_{value_name}); // {}\n", file.ident);
                        out.push_str(&line);
                    } else {
                        let line = format!("    char* {value_name} = path_{value_name}; // {}\n", file.ident);
                        out.push_str(&line);
                    }
                }
                _ => {}
            }
        }
        out.push_str("}\n");
        let beginning = out.find("int main() {").unwrap();
        let callbacks = translate_callbacks_to_c(&callbacks)?;
        out.insert_str(beginning, &callbacks);
        Ok(out)
    }
}

fn translate_callbacks_to_c(callbacks: &HashSet<String>) -> eyre::Result<String> {
    let mut ret = String::new();

    let mut alias_cnt = 0;
    for callback in callbacks {
        crate::log!(trace, "translating {callback}");
        let fn_g = global_gadgets::get_instance()
            .functions
            .get(callback)
            .context("no such callback")?;

        let mut arg_list = String::new();
        for (arg_type, arg_ident) in fn_g.arg_types.iter().zip(fn_g.arg_idents.iter()) {
            let arg = get_c_left_operand(arg_ident, arg_type);
            arg_list.push_str(format!("{arg}, ").as_str());
        }
        // leave the ending comma and whitespace
        arg_list.pop();
        arg_list.pop();

        let (ret_ty_and_fn_name, body) = {
            let mut ret_ty_and_fn_name = String::new();
            let mut body = String::new();
            let ret_ty = fn_g.ret_type.unwrap_or("void");

            if ret_ty.contains("core::option::Option<unsafe extern \"C\" fn(") {
                // For callbacks that return function pointer, create a alias to the return type.
                let alias_name = format!("callback_func_ptr_t_{alias_cnt}");
                alias_cnt += 1;
                let alias_declare = get_c_left_operand(&alias_name, ret_ty);
                writeln!(ret_ty_and_fn_name, "typedef {alias_declare};")?;
                write!(ret_ty_and_fn_name, "{alias_name} {callback}")?;
                write!(
                    body,
                    "    return *({alias_name} *)calloc(1, sizeof({alias_name}));"
                )?;
            } else {
                write!(
                    ret_ty_and_fn_name,
                    "{}",
                    get_c_left_operand(callback, ret_ty)
                )?;
                if ret_ty != "void" {
                    let ret_ty = get_c_left_operand("PLACEHOLDER", ret_ty).replace("PLACEHOLDER", "");
                    write!(body, "    return *({ret_ty} *)calloc(1, sizeof({ret_ty}));")?;
                }
            }

            (ret_ty_and_fn_name, body)
        };

        write!(ret, "{ret_ty_and_fn_name}({arg_list}) {{\n{body}\n}}\n")
            .expect("'write!' error in 'translate_callbacks_to_c'");
    }

    Ok(ret)
}

fn get_c_left_operand(value_name: &str, ty: &str) -> String {
    let mut next = ty.trim();
    let mut value_name = value_name.to_string();
    let c_ty;
    loop {
        if let Some(start) = find_next(next, "alloc::vec::Vec<") {
            // should stored in heap
            let end = next.len() - 1;
            next = &next[start..end];
            value_name += "[]";
        } else if let Some(start) = find_next(next, "[") {
            let end = next.rfind(';').unwrap();
            // let array_len =
            next = &next[start..end];
            value_name += "[]";
        } else if let Some(start) = find_next(next, "hopper::runtime::FuzzMutPointer<") {
            let end = next.len() - 1;
            next = &next[start..end];
            value_name = "*".to_string() + &value_name;
        } else if let Some(start) = find_next(next, "hopper::runtime::FuzzConstPointer<") {
            let end = next.len() - 1;
            next = &next[start..end];
            value_name = "*".to_string() + &value_name;
        } else if let Some(start) = find_next(next, "hopper::runtime::FuzzFrozenPointer<") {
            let end = next.len() - 1;
            next = &next[start..end];
        } else if let Some(start) = find_next(next, "core::option::Option<unsafe extern \"C\" fn(")
        {
            let end = next.len() - 1;
            next = &next[start..end];
            if let Some((args, ret)) = next.split_once(')') {
                let arg_tys = args
                    .trim()
                    .split(',')
                    .map(|ty| get_c_left_operand("", ty))
                    .collect::<Vec<String>>()
                    .join(",");
                let ret = ret.replace("->", "");
                let ret = ret.trim();
                if ret.is_empty() {
                    c_ty = "void".to_string();
                } else {
                    c_ty = get_c_left_operand("", ret);
                }
                value_name = format!("(*{value_name})({arg_tys})");
                break;
            }
        } else if utils::is_void_type(next) {
            c_ty = "void".to_string();
            break;
        } else {
            if let Some(n) = next.strip_prefix("hopper_harness::") {
                // c_ty = format!("struct {}", n);
                c_ty = n.to_string();
            } else {
                c_ty = next.to_string();
            }
            break;
        }
    }
    crate::log!(
        trace,
        "rust: {}, ty: {}, value_name: {}",
        ty,
        c_ty,
        value_name
    );
    format!("{c_ty} {value_name}")
}

fn find_next(cur: &str, pat: &str) -> Option<usize> {
    if cur.starts_with(pat) {
        return Some(pat.len());
    }
    None
}
