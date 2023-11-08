///! Implementation general function for both foreign and internal functions.
///! Ref: https://docs.rs/syn/1.0.76/src/syn/item.rs.html#611-622
///! WARN: Deprecated!!

use std::{iter, slice};

use proc_macro2::TokenStream;
use quote::{ToTokens, TokenStreamExt};
use syn::{
    braced, bracketed,
    parse::{Parse, ParseStream, Result},
    AttrStyle, Attribute, Block, Path, Signature, Token, Visibility,
};
pub struct FnDecl {
    pub attrs: Vec<Attribute>,
    pub vis: Visibility,
    pub sig: Signature,
    pub block: Option<Box<Block>>,
    pub semi_token: Option<Token![;]>,
}

impl Parse for FnDecl {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut attrs = input.call(Attribute::parse_outer)?;
        let vis: Visibility = input.parse()?;
        let sig: Signature = input.parse()?;
        let lookahead = input.lookahead1();
        let mut block = None;
        let mut semi_token = None;
        if lookahead.peek(Token![;]) {
            // ForeignItemFn
            let semi: Token![;] = input.parse()?;
            semi_token = Some(semi);
        } else if lookahead.peek(syn::token::Brace) {
            // ItemFn
            let content;
            let brace_token = braced!(content in input);
            parse_inner(&content, &mut attrs)?;
            let stmts = content.call(Block::parse_within)?;
            block = Some(Box::new(Block { brace_token, stmts }));
        } else {
            return Err(lookahead.error());
        };

        Ok(FnDecl {
            attrs,
            vis,
            sig,
            block,
            semi_token
        })
    }
}

impl ToTokens for FnDecl {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.append_all(self.attrs.outer());
        self.vis.to_tokens(tokens);
        self.sig.to_tokens(tokens);
        if let Some(blk) = &self.block {
            blk.brace_token.surround(tokens, |tokens| {
                tokens.append_all(self.attrs.inner());
                tokens.append_all(&blk.stmts);
            });
        } 
        if let Some(semi) = &self.semi_token {
            semi.to_tokens(tokens);
        }
    }
}

pub fn parse_inner(input: ParseStream, attrs: &mut Vec<Attribute>) -> Result<()> {
    while input.peek(Token![#]) && input.peek2(Token![!]) {
        attrs.push(input.call(single_parse_inner)?);
    }
    Ok(())
}

pub fn single_parse_inner(input: ParseStream) -> Result<Attribute> {
    let content;
    Ok(Attribute {
        pound_token: input.parse()?,
        style: AttrStyle::Inner(input.parse()?),
        bracket_token: bracketed!(content in input),
        path: content.call(Path::parse_mod_style)?,
        tokens: content.parse()?,
    })
}


pub trait FilterAttrs<'a> {
    type Ret: Iterator<Item = &'a Attribute>;

    fn outer(self) -> Self::Ret;
    fn inner(self) -> Self::Ret;
}

impl<'a> FilterAttrs<'a> for &'a [Attribute] {
    type Ret = iter::Filter<slice::Iter<'a, Attribute>, fn(&&Attribute) -> bool>;

    fn outer(self) -> Self::Ret {
        fn is_outer(attr: &&Attribute) -> bool {
            match attr.style {
                AttrStyle::Outer => true,
                AttrStyle::Inner(_) => false,
            }
        }
        self.iter().filter(is_outer)
    }

    fn inner(self) -> Self::Ret {
        fn is_inner(attr: &&Attribute) -> bool {
            match attr.style {
                AttrStyle::Inner(_) => true,
                AttrStyle::Outer => false,
            }
        }
        self.iter().filter(is_inner)
    }
}
