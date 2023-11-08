use hopper_derive::Serde;

#[derive(Debug, Clone, Serde, PartialEq, Eq)]
pub struct CallContext {
    pub f_name: String,
    pub related_arg_pos: Option<usize>,
    pub kind: ContextKind
}

#[derive(Debug, Clone, Serde, PartialEq, Eq)]
pub enum ContextKind {
    Required,
    Prefered,
    Forbidden
}

impl CallContext {
    pub fn from_rule(de: &mut crate::Deserializer) -> eyre::Result<Self>{
        let related_arg_pos = if de.strip_token("-") || de.strip_token("*") {
            None
        } else {
            de.eat_token("$")?;
            let arg_i: usize = de.parse_number()?;
            Some(arg_i)
        };
        de.eat_token("]")?;
        de.eat_token("<-")?;
        let mut kind = ContextKind::Required;
        let mut f_name = de.buf.trim().trim_end_matches(';');
        if let Some(f) = f_name.strip_prefix('!') {
            f_name = f.trim();
            kind = ContextKind::Forbidden;
        } else if let Some(f) = f_name.strip_suffix('?') {
            f_name = f.trim();
            kind = ContextKind::Prefered;
        }
        Ok(Self {
            f_name: f_name.to_string(),
            related_arg_pos,
            kind,
        })
    }

    pub fn is_required(&self) -> bool {
        matches!(self.kind, ContextKind::Required)
    }

    pub fn is_preferred(&self) -> bool {
        matches!(self.kind, ContextKind::Prefered)
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(self.kind, ContextKind::Forbidden)
    }
}
