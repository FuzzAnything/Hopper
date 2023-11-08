//! Trait for serialize and deserialize program

use std::str::FromStr;

use eyre::Context;
use num::Float;

use super::*;

/// Trait for serialize runtime irs without states, e.g. program, call, value
pub trait Serialize {
    fn serialize(&self) -> eyre::Result<String>;
}

/// Serialize for object values with states
pub trait ObjectSerialize {
    fn serialize_obj(&self, state: &ObjectState) -> eyre::Result<String>;
}

/// Structure that maintains string buffer, and implements useful functions for deserialize.
pub struct Deserializer<'a> {
    pub buf: &'a str,
    /// program is used to serialize/deserialize index
    pub program: Option<&'a mut FuzzProgram>,
    pub canary: bool,
}

/// Trait for deserialize runtime irs without states, e.g. program, call
pub trait Deserialize: Sized {
    fn deserialize(de: &mut Deserializer) -> eyre::Result<Self>;
}

/// Deserialize for object values with states
pub trait ObjectDeserialize: Sized {
    fn deserialize_obj(de: &mut Deserializer, state: &mut ObjectState) -> eyre::Result<Self>;
}

impl<'a> Deserializer<'a> {
    pub fn new(buf: &'a str, program: Option<&'a mut FuzzProgram>) -> Self {
        let buf = buf.trim();
        Self {
            buf,
            program,
            canary: false,
        }
    }

    pub fn peek_char(&self) -> Option<char> {
        self.buf.chars().next()
    }

    pub fn next_char(&mut self) -> Option<char> {
        let mut chars = self.buf.chars();
        let c = chars.next();
        self.buf = chars.as_str();
        c
    }

    pub fn strip_token(&mut self, token: &str) -> bool {
        if let Some(buf) = self.buf.strip_prefix(token) {
            self.buf = buf;
            return true;
        }
        false
    }

    pub fn eat_token(&mut self, token: &str) -> eyre::Result<()> {
        self.buf = self
            .buf
            .strip_prefix(token)
            .ok_or_else(|| eyre::eyre!("`{}` should start with `{}`", self.buf, token))?;
        self.trim_start();
        Ok(())
    }

    pub fn next_token_until(&mut self, del: &str) -> eyre::Result<&'a str> {
        let (token, buf) = self
            .buf
            .split_once(del)
            .ok_or_else(|| eyre::eyre!("`{}` can not split by `{}`", self.buf, del))?;
        self.buf = buf;
        self.trim_start();
        Ok(token)
    }

    pub fn eat_ty(&mut self) -> eyre::Result<&'a str> {
        // crate::log!(warn, "self.buf before: {:?}", self.buf);
        let mut opened = 0;
        let mut index = 0;
        let mut it = self.buf.chars();
        while let Some(c) = it.next() {
            // crate::log!(warn, "c: {}, opened: {}", c, opened);
            match c {
                '<' | '(' | '[' => {
                    opened += 1;
                    index += 1;
                }
                '>' | ')' | ']' => {
                    opened -= 1;
                    index += 1;
                }
                ',' => {
                    if opened == 0 {
                        break;
                    }
                    index += 1;
                }
                '-' => {
                    it.next();
                    index += 2;
                }
                _ => {
                    index += 1;
                }
            }
        }
        let (ty, buf) = self.buf.split_at(index);
        self.buf = buf;
        // crate::log!(warn, "self.buf: {:?}", self.buf);
        self.eat_token(",")
            .with_context(|| format!("failed to eat ty: ty: {ty} buf: {buf}"))?;
        self.trim_start();
        Ok(ty)
    }

    pub fn parse_next_until<T: FromStr>(&mut self, del: &str) -> eyre::Result<T> {
        let token = self.next_token_until(del)?;
        match token.parse() {
            Ok(v) => Ok(v),
            Err(_) => Err(eyre::eyre!("fail to parse `{}`", token)),
        }
    }

    pub fn parse_float<T: Float + FromStr>(&mut self) -> eyre::Result<T> {
        if self.strip_token("NaN") {
            return Ok(Float::nan());
        }
        if self.strip_token("inf") {
            return Ok(Float::infinity());
        }
        if self.strip_token("-inf") {
            return Ok(Float::neg_infinity());
        }
        let mut len = 0;
        for c in self.buf.chars() {
            match c {
                '0'..='9' | '-' | '.' => {}
                _ => {
                    break;
                }
            }
            len += 1;
        }
        eyre::ensure!(len > 0, "`{}` is not float`", self.buf);
        let token = &self.buf[..len];
        self.buf = &self.buf[len..];
        self.trim_start();
        match token.parse() {
            Ok(v) => Ok(v),
            Err(_) => Err(eyre::eyre!("fail to parse `{}` as float", token)),
        }
    }

    pub fn parse_number<T: FromStr>(&mut self) -> eyre::Result<T> {
        let mut len = 0;
        for c in self.buf.chars() {
            match c {
                '0'..='9' | '-' => {}
                _ => {
                    break;
                }
            }
            len += 1;
        }
        eyre::ensure!(len > 0, "`{}` is not number`", self.buf);
        let token = &self.buf[..len];
        self.buf = &self.buf[len..];
        self.trim_start();
        match token.parse() {
            Ok(v) => Ok(v),
            Err(_) => Err(eyre::eyre!("fail to parse `{}` as number", token)),
        }
    }

    pub fn parse_string(&mut self) -> eyre::Result<String> {
        let mut len = 0;
        for c in self.buf.chars() {
            match c {
                '0'..='9' | 'a'..='z' | 'A'..='Z' | '_' => {}
                _ => {
                    break;
                }
            }
            len += 1;
        }
        eyre::ensure!(len > 0, "`{}` is not string`", self.buf);
        let token = &self.buf[..len];
        self.buf = &self.buf[len..];
        self.trim_start();
        Ok(token.to_string())
    }

    pub fn trim_start(&mut self) {
        self.buf = self.buf.trim_start();
    }

    pub fn as_str(&self) -> &str {
        self.buf
    }
}

#[inline]
fn serialize_option_str<T: ToString>(out: &mut String, opt: &Option<T>) {
    if let Some(inner) = opt {
        out.push_str(&inner.to_string());
    } else {
        out.push_str("None");
    }
}

/// Serialize FuzzProgram
///
/// The output looks like:
/// <HEADEAR> ID: 1, Prarent: None
/// <0> load [type] = [data]
/// <1> call [func_name] (<1>, <2>)
/// <END>
/// <OP> ...
impl Serialize for FuzzProgram {
    fn serialize(&self) -> eyre::Result<String> {
        let mut out = String::with_capacity(1024);
        out.push_str("<HEADER> ID: ");
        out.push_str(&self.id.to_string());
        out.push_str(", Parent: ");
        serialize_option_str(&mut out, &self.parent);
        out.push_str(",\n");
        for indexed_stmt in self.stmts.iter() {
            let stmt_str = &indexed_stmt
                .serialize()
                .with_context(|| format!("fail to serialize stmt: {indexed_stmt:?}"))?;
            out.push_str(stmt_str);
        }
        out.push_str("<END>\n");
        Ok(out)
    }
}

/// Deseialize FuzzProgram
///
/// We do implement the deserialize function here, and use `read_program` instead.
impl Deserialize for FuzzProgram {
    fn deserialize(_de: &mut Deserializer) -> eyre::Result<Self> {
        // use `read_program` for deserialize
        unimplemented!();
    }
}

/// Read program from a reader argument.
///
/// Invokes deserialize function recursively.
pub fn read_program(buf: &str, canary: bool) -> eyre::Result<FuzzProgram> {
    let mut program = FuzzProgram::default();
    let mut lines = buf.lines();
    let first = match lines.next() {
        Some(l) => l,
        _ => {
            eyre::bail!("fail to read first line from buffer");
        }
    };
    // parse header
    let mut de = Deserializer::new(first, None);
    de.eat_token("<HEADER>")?;
    de.eat_token("ID:")?;
    let id: usize = de.parse_number().context("fail to parse id")?;
    de.eat_token(",")?;
    de.eat_token("Parent:")?;
    let mut parent = None;
    if !de.strip_token("None") {
        parent = Some(de.parse_number().context("fail to parse parent")?);
    }
    de.eat_token(",")?;
    program.id = id;
    program.parent = parent;
    // parse stmts
    for line in lines {
        let mut de = Deserializer::new(line, Some(&mut program));
        de.canary = canary;
        if de.strip_token("<END>") {
            break;
        }
        let is = IndexedStmt::deserialize(&mut de)
            .with_context(|| format!("fail to deserialize: {line}"))?;
        program.stmts.push(is);
    }
    program.clear_tmp_indices()?;
    Ok(program)
}

/// Parse ops, flags, and rng state
pub fn parse_program_extra(buf: &str, program: &mut FuzzProgram) -> eyre::Result<()> {
    for line in buf.lines() {
        let mut de = Deserializer::new(line, Some(program));
        if de.strip_token("<RNG>") {
            de.trim_start();
            let rng_state = crate::RngState::deserialize(&mut de)?;
            program.rng = Some(rng_state);
        } else if de.strip_token("<FLAG>") {
            de.trim_start();
            program.mutate_flag = de.parse_number()?;
        } else if de.strip_token("<OP>") {
            de.trim_start();
            program.ops = Vec::<crate::MutateOperator>::deserialize(&mut de)?;
        }
    }
    Ok(())
}

/// Read value based on its type
pub fn read_value(
    de: &mut Deserializer,
    ty: &str,
    state: &mut ObjectState,
) -> eyre::Result<FuzzObject> {
    // case for vec
    if let Some(v_ty) = ty.strip_prefix("alloc::vec::Vec<") {
        let ty = v_ty
            .strip_suffix('>')
            .ok_or_else(|| eyre::eyre!("should end with `>`"))?;
        global_gadgets::get_instance()
            .get_object_builder(ty)?
            .deserialize_vec(de, state)
    } else {
        global_gadgets::get_instance()
            .get_object_builder(ty)?
            .deserialize(de, state)
    }
}

#[test]
fn test_program_serde() {
    fn serialize_and_deserialize(target: &'static str) {
        crate::config::get_config_mut().func_target = Some(target);
        let program = FuzzProgram::generate_program(None, false).unwrap();
        let output = program.serialize().unwrap();
        println!("program {target}");
        println!("{}", &output);

        let read_back = read_program(&output, false).unwrap();
        let output2 = read_back.serialize().unwrap();
        println!("read back: {target}");
        println!("{output2}");
        assert_eq!(output, output2);
    }

    for _ in 0..16 {
        serialize_and_deserialize("func_add");
        serialize_and_deserialize("func_create");
        serialize_and_deserialize("func_use");
        serialize_and_deserialize("func_struct");
    }
}

#[test]
fn test_freed_serde() {
    let mut p = FuzzProgram::default();
    p.append_stmt(FuzzStmt::Assert(AssertStmt::default().into()));
    p.append_stmt(FuzzStmt::Assert(AssertStmt::default().into()));
    let last = p.append_stmt(FuzzStmt::Assert(AssertStmt::default().into()));
    p.stmts[0].freed = Some(last.downgrade());
    let output = p.serialize().unwrap();
    println!("{output}");
    let read_back = read_program(&output, false).unwrap();
    let output2 = read_back.serialize().unwrap();
    assert_eq!(output, output2);
}
