use eyre::ContextCompat;
use hopper_derive::Serde;

use crate::{FieldKey, LocFields};

#[derive(Debug, Clone, Serde, PartialEq, Eq)]
pub enum IrEntry {
    Min(i32),
    Max(i32),
    Constant(u64),
    String(String),
    Length {
        arg_pos: Option<usize>,
        fields: LocFields,
        is_factor: bool,
    },
    Location {
        arg_pos: Option<usize>,
        fields: LocFields,
    },
}

impl IrEntry {
    pub fn arg_length(arg_pos: usize) -> IrEntry {
        Self::Length {
            arg_pos: Some(arg_pos),
            fields: LocFields::default(),
            is_factor: false,
        }
    }

    pub fn field_length(field_key: FieldKey) -> IrEntry {
        Self::Length {
            arg_pos: None,
            fields: LocFields::new(vec![field_key]),
            is_factor: false,
        }
    }

    pub fn is_fixed(&self) -> bool {
        matches!(self, Self::Constant(_) | Self::String(_))
    }

    pub fn is_factor(&self) -> bool {
        if let Self::Length {
            arg_pos: _,
            fields: _,
            is_factor,
        } = self
        {
            *is_factor
        } else {
            false
        }
    }

    pub fn is_length(&self) -> bool {
        matches!(
            self,
            Self::Length {
                arg_pos: _,
                fields: _,
                is_factor: _
            }
        )
    }

    pub fn get_location_from_any(&self) -> Option<(&Option<usize>, &LocFields)> {
        match self {
            Self::Location { arg_pos, fields } => Some((arg_pos, fields)),
            Self::Length { arg_pos, fields, is_factor: _ } => Some((arg_pos, fields)),
            _ => None
        }
    }

    /// compare without consider `is_factor`
    pub fn equal(&self, other: &Self) -> bool {
        if let Self::Length {
            arg_pos: arg_pos1,
            fields: fields1,
            is_factor: _,
        } = self
        {
            if let Self::Length {
                arg_pos: arg_pos2,
                fields: fields2,
                is_factor: _,
            } = other
            {
                return arg_pos1 == arg_pos2 && fields1 == fields2;
            }
        }
        self == other
    }

    /// If `self` is less or equal than `other`
    /// we assume the length is not less than constant
    pub fn less(&self, other: &Self) -> bool {
        if let Self::Constant(val) = self {
            if let Self::Constant(val2) = other {
                return val <= val2;
            }
        }
        other.is_length()
    }

    /// If `self` is greater or equal than `other`
    /// we assume the length is not greater than constant
    pub fn greater(&self, other: &Self) -> bool {
        if let Self::Constant(val) = self {
            if let Self::Constant(val2) = other {
                return val >= val2;
            }
        }
        other.is_length()
    }

    pub fn from_rule(de: &mut crate::Deserializer) -> eyre::Result<Self> {
        if de.strip_token("MIN") {
            de.trim_start();
            let mut offset = 0;
            if de.strip_token("+") {
                offset = de.parse_number()?;
            }
            return Ok(Self::Min(offset));
        } else if de.strip_token("MAX") {
            de.trim_start();
            let mut offset = 0;
            if de.strip_token("-") {
                offset = de.parse_number()?;
            }
            return Ok(Self::Max(offset));
        }
        let c = de.peek_char().context("has char")?;
        match c {
            '$' => {
                de.eat_token("$")?;
                let is_len = de.strip_token("len(");
                let mut arg_pos = None;
                let mut fields = LocFields::default();
                if de.strip_token("$") || de.peek_char().filter(|c| c.is_ascii_digit()).is_some() {
                    arg_pos = Some(de.parse_number()?);
                }
                if arg_pos.is_none() && de.strip_token("[") && de.strip_token("$") {
                    arg_pos = Some(de.parse_number()?);
                    de.eat_token("]")?;
                    if de.strip_token("[") {
                        fields = LocFields::from_rule(de.next_token_until("]")?)?;
                    }
                }
                if arg_pos.is_none() && fields.is_empty() && !de.buf.is_empty() {
                    fields = LocFields::from_rule(de.buf)?;
                }
                if is_len {
                    Ok(Self::Length {
                        arg_pos,
                        fields,
                        is_factor: false,
                    })
                } else {
                    Ok(Self::Location { arg_pos, fields })
                }
            }
            '[' => {
                de.eat_token("[")?;
                de.eat_token("$")?;
                let arg_pos = Some(de.parse_number()?);
                de.eat_token("]")?;
                let fields = if de.strip_token("[") {
                    LocFields::from_rule(de.next_token_until("]")?)?
                } else {
                    LocFields::default()
                };
                Ok(Self::Location { arg_pos, fields })
            }
            '"' => {
                de.eat_token("\"")?;
                let token = de.next_token_until("\"")?;
                Ok(Self::String(token.to_string()))
            }
            '0'..='9' | '-' => {
                let val = de.parse_number()?;
                Ok(Self::Constant(val))
            }
            _ => {
                eyre::bail!("wrong rule fo ir entry: {}", de.buf);
            }
        }
    }
}

impl From<u64> for IrEntry {
    fn from(i: u64) -> Self {
        Self::Constant(i)
    }
}

impl From<usize> for IrEntry {
    fn from(i: usize) -> Self {
        Self::Constant(i as u64)
    }
}

impl From<i32> for IrEntry {
    fn from(i: i32) -> Self {
        Self::Constant(i as u64)
    }
}

#[test]
fn test_parse_entry() {
    let ret = IrEntry::from_rule(&mut crate::Deserializer::new("$0", None)).unwrap();
    assert_eq!(
        ret,
        IrEntry::Location {
            arg_pos: Some(0),
            fields: LocFields::default()
        }
    );
    let ret = IrEntry::from_rule(&mut crate::Deserializer::new("[$1][&.$0.name]", None)).unwrap();
    assert_eq!(
        ret,
        IrEntry::Location {
            arg_pos: Some(1),
            fields: LocFields {
                list: vec![FieldKey::Pointer, 0.into(), "name".into()]
            }
        }
    );
    let ret = IrEntry::from_rule(&mut crate::Deserializer::new("$len($1)", None)).unwrap();
    assert_eq!(
        ret,
        IrEntry::Length {
            arg_pos: Some(1),
            fields: LocFields::default(),
            is_factor: false
        }
    );
    let ret =
        IrEntry::from_rule(&mut crate::Deserializer::new("$len([$1][&.$0.name])", None)).unwrap();
    assert_eq!(
        ret,
        IrEntry::Length {
            arg_pos: Some(1),
            fields: LocFields {
                list: vec![FieldKey::Pointer, 0.into(), "name".into()]
            },
            is_factor: false
        }
    );
}
