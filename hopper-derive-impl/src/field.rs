//! Fields

use proc_macro2::{Span, TokenStream};
use syn::punctuated::Punctuated;
use syn::{Token, Type};

use crate::my_quote;

pub struct FieldExt<'a> {
    pub ty: &'a syn::Type,
    pub ident: syn::Ident,
    pub named: bool,
}

impl<'a> FieldExt<'a> {
    pub fn new(field: &'a syn::Field, idx: usize, named: bool) -> FieldExt<'a> {
        FieldExt {
            ty: &field.ty,
            ident: if named {
                field.ident.clone().unwrap()
            } else {
                syn::Ident::new(&format!("f{idx}"), proc_macro2::Span::call_site())
            },
            named,
        }
    }

    pub fn is_phantom_data(&self) -> bool {
        match *self.ty {
            syn::Type::Path(syn::TypePath {
                qself: None,
                ref path,
            }) => path
                .segments
                .last()
                .map(|x| x.ident == "PhantomData")
                .unwrap_or_else(|| false),
            _ => false,
        }
    }

    pub fn init_phantom(&self, field_name: &str, ty: &Type) -> TokenStream {
        let ph = if cfg!(feature = "std") {
            my_quote!(::std::marker::PhantomData)
        } else {
            my_quote!(::core::marker::PhantomData)
        };
        my_quote!({
            let state = state.add_child(#field_name, std::any::type_name::<#ty>()).last_child()?;
            state.done_deterministic_itself();
            #ph
        })
    }

    pub fn get_field_value(&self, use_self: bool) -> TokenStream {
        let ident = &self.ident;
        if use_self {
            if self.named {
                my_quote!(self.#ident)
            } else {
                my_quote!(self.0)
            }
        } else {
            my_quote!(#ident)
        }
    }

    pub fn is_opaque(&self) -> bool {
        self.named && self.ident.to_string().starts_with("_bindgen_opaque")
    }
}

pub fn convert_fields(fields: &syn::Fields) -> (Vec<FieldExt>, bool, bool) {
    let (fields, named) = match *fields {
        syn::Fields::Named(ref fields) => (Some(&fields.named), true),
        syn::Fields::Unit => (None, false),
        syn::Fields::Unnamed(ref fields) => (Some(&fields.unnamed), false),
    };
    let unit = fields.is_none();
    let fields = convert_field_list(fields, named);
    (fields, named, unit)
}

pub fn convert_field_list(
    fields: Option<&Punctuated<syn::Field, Token![,]>>,
    named: bool,
) -> Vec<FieldExt> {
    if let Some(fields) = fields {
        fields
            .iter()
            .enumerate()
            .map(|(i, f)| FieldExt::new(f, i, named))
            .collect()
    } else {
        vec![]
    }
}

pub fn list_field_keys(fields: &[FieldExt], named: bool) -> TokenStream {
    let fields = fields.iter().map(|f| &f.ident);
    let fields = my_quote![ #(#fields),* ];
    if named {
        my_quote!({ #fields })
    } else {
        my_quote!(( #fields ))
    }
}

pub fn struct_object_gen_body(fields: &[FieldExt], unit: bool, named: bool) -> TokenStream {
    let inits = fields.iter().map(|f| {
        let field = &f.ident;
        let field_name = field.to_string();
        let ty = f.ty;
        let init = if f.is_phantom_data() {
            f.init_phantom(&field_name, ty)
        } else {
            my_quote!(<#ty>::generate_new(state.add_child(#field_name, std::any::type_name::<#ty>()).last_child_mut()?)?)
        };
        if f.named {
            my_quote!(#field: #init)
        } else {
            my_quote!(#init)
        }
    });
    if unit {
        my_quote!()
    } else if named {
        my_quote![{ #(#inits),* }]
    } else {
        // unnamed
        my_quote![( #(#inits),* )]
    }
}

pub fn union_object_gen_body(fields: &[FieldExt]) -> TokenStream {
    let gens = fields
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let field = &f.ident;
            let field_name = field.to_string();
            let ty = f.ty;
            let index = syn::LitInt::new(&i.to_string(), Span::call_site());
            my_quote!(#index => Self { #field: <#ty>::generate_new(state.add_child(#field_name, std::any::type_name::<#ty>()).last_child_mut()?)? })
        });
    let crate_path = super::get_crate_path();
    let items = my_quote![ #(#gens),* ];
    let field_size = fields.len();
    let size_ident = syn::LitInt::new(&field_size.to_string(), Span::call_site());
    my_quote!(
        match #crate_path::gen_range(0..#size_ident) {
            #items,
            _ => { unreachable!() },
        }
    )
}

pub fn struct_object_layout_body(fields: &[FieldExt], unit: bool) -> TokenStream {
    let fields = fields.iter().map(|f| {
        if f.is_phantom_data() {
            return my_quote!();
        }
        let field = &f.ident;
        let field_name = field.to_string();
        let value = f.get_field_value(true);
        my_quote!(layout.add_field(#field_name, #value.get_layout(fold_ptr));)
    });
    if unit {
        my_quote!()
    } else {
        my_quote![ #(#fields)* ]
    }
}

pub fn struct_object_mutate_body(fields: &[FieldExt], unit: bool, is_det: bool) -> TokenStream {
    if unit {
        return my_quote!();
    }
    let mutates = fields.iter().enumerate().map(|(i, f)| {
        let field = &f.ident;
        let field_name = field.to_string();
        let index = syn::LitInt::new(&i.to_string(), Span::call_site());
        let value = f.get_field_value(true);
        if f.is_phantom_data() {
            my_quote!(#index => {})
        } else if is_det {
            my_quote!(#index => { #value.det_mutate(state.get_child_mut(#field_name)?) })
        } else {
            my_quote!(#index => { #value.mutate(state.get_child_mut(#field_name)?) })
        }
    });
    let crate_path = super::get_crate_path();
    let items = my_quote![ #(#mutates),* ];
    let choose_index = if is_det {
        my_quote!(state.get_deterministic_child_position())
    } else {
        my_quote!(#crate_path::choose_weighted_by_state(state))
    };
    let ret_nop = if is_det {
        my_quote!(
            state.done_deterministic();
            Ok(#crate_path::MutateOperator::nop())
        )
    } else {
        my_quote!(Ok(#crate_path::MutateOperator::nop()))
    };
    my_quote!(
        if let Some(index) = #choose_index {
            match index {
                #items,
                _ => { unreachable!() },
            }
        } else {
            #ret_nop
        }
    )
}

pub fn union_object_mutate_body(fields: &[FieldExt]) -> TokenStream {
    let mutates = fields.iter().map(|f| {
        let field = &f.ident;
        let field_name = field.to_string();
        let value = f.get_field_value(true);
        // state is chosen outside
        my_quote!(#field_name => { #value.mutate(state) })
    });
    let items = my_quote![ #(#mutates),* ];
    let crate_path = super::get_crate_path();
    my_quote!(
        if #crate_path::unlikely() {
            use #crate_path::ObjGenerate;
            state.clear();
            let rng_state = #crate_path::save_rng_state();
            *self = Self::generate_new(state)?;
            return Ok(state.as_mutate_operator(#crate_path::MutateOperation::UnionNew { rng_state } ));
        }
    unsafe {
        let state = state.last_child_mut()?;
        let key = state.key.as_str()?;
        match key {
            #items,
            _ => { unreachable!() },
        }
    }
    )
}

pub fn struct_object_mutate_op_body(fields: &[FieldExt], unit: bool) -> TokenStream {
    if unit {
        return my_quote!(Ok(self as *mut Self as *mut u8));
    }
    let raws = fields.iter().map(|f| {
        let field = &f.ident;
        let field_name = field.to_string();
        let value = f.get_field_value(true);
        my_quote!(#field_name => {return #value.mutate_by_op( state.get_child_mut(#field_name)?, &keys[1..], op);})
    });
    let items = my_quote![ #(#raws),* ];
    my_quote!(
        if keys.is_empty() {
            eyre::bail!(format!("keys: {:?} and op {:?} does not works in struct", keys, op));
        }
        let key = keys[0].as_str()?;
        match key {
            #items,
            _ => { unreachable!("key {} not found", key) },
        }
    )
}

pub fn struct_object_opaque_body(fields: &[FieldExt]) -> TokenStream {
    let is_opaque = fields.iter().any(|f| f.is_opaque());
    if is_opaque {
        return my_quote!(true);
    }
    let mut check_opaque = fields.iter().map(|f| {
        let ty = f.ty;
        my_quote!(<#ty>::is_opaque())
    });
    let mut ret = if let Some(first) = check_opaque.next() {
        first
    } else {
        my_quote!()
    };
    for item in check_opaque {
        ret = my_quote!(#ret || #item);
    }
    ret
}

pub fn struct_object_ptr_body(fields: &[FieldExt], unit: bool) -> TokenStream {
    if unit {
        return my_quote!(Ok(self as *mut Self as *mut u8));
    }
    let raws = fields.iter().map(|f| {
        let field = &f.ident;
        let field_name = field.to_string();
        let value = f.get_field_value(true);
        my_quote!(#field_name => #value.get_ptr_by_keys(&keys[1..]))
    });
    let items = my_quote![ #(#raws),* ];
    my_quote!(
        if keys.is_empty() {
            return Ok(self as *const Self as *mut Self as *mut u8);
        }
        let key = keys[0].as_str()?;
        match key {
            #items,
            _ => { unreachable!() },
        }
    )
}

pub fn struct_object_serialize_body(fields: &[FieldExt], use_self: bool) -> TokenStream {
    let buf_ident = syn::Ident::new("buf", Span::call_site());
    let sers = fields.iter().map(|f| {
        if f.is_phantom_data() {
            return my_quote!();
        }
        let field = &f.ident;
        let field_name = field.to_string();
        let value = f.get_field_value(use_self);
        let header = format!("{field}: ");
        my_quote!(
            #buf_ident.push_str(#header);
            #buf_ident.push_str(&#value.serialize_obj(state.get_child(#field_name)?)?);
            #buf_ident.push_str(", ");
        )
    });
    my_quote!( #(#sers)* )
}

pub fn struct_object_translate_body(fields: &[FieldExt], use_self: bool) -> TokenStream {
    let buf_ident = syn::Ident::new("buf", Span::call_site());
    let sers = fields.iter().map(|f| {
        if f.is_phantom_data() {
            return my_quote!();
        }
        let field = &f.ident;
        let field_name = field.to_string();
        let value = f.get_field_value(use_self);
        my_quote!(
            #buf_ident.push_str(&#value.translate_obj_to_c(state.get_child(#field_name)?, program)?);
            #buf_ident.push_str(", ");
        )
    });
    my_quote!( #(#sers)* )
}

pub fn struct_serialize_body(fields: &[FieldExt], use_self: bool) -> TokenStream {
    let buf_ident = syn::Ident::new("buf", Span::call_site());
    let sers = fields.iter().map(|f| {
        if f.is_phantom_data() {
            return my_quote!();
        }
        let field = &f.ident;
        let header = format!("{field}: ");
        let value = f.get_field_value(use_self);
        my_quote!(
            #buf_ident.push_str(#header);
            #buf_ident.push_str(&#value.serialize()?);
            #buf_ident.push_str(", ");
        )
    });
    my_quote!( #(#sers)* )
}

pub fn union_object_serialize_body(fields: &[FieldExt], use_self: bool) -> TokenStream {
    let buf_ident = syn::Ident::new("buf", Span::call_site());
    let sers = fields.iter().map(|f| {
        let field = &f.ident;
        let field_name = field.to_string();
        let header = format!("{field}: ");
        let value = f.get_field_value(use_self);
        // state is chosen outside
        my_quote!(#field_name => {
            #buf_ident.push_str(#header);
            #buf_ident.push_str(&#value.serialize_obj(state)?)
        })
    });
    let items = my_quote![ #(#sers),* ];
    my_quote!(
    unsafe {
        let state = state.last_child()?;
        let key = state.key.as_str()?;
        match key {
            #items,
            _ => { unreachable!() },
        }
    }
    )
}

pub fn union_object_translate_body(fields: &[FieldExt], use_self: bool) -> TokenStream {
    let buf_ident = syn::Ident::new("buf", Span::call_site());
    let sers = fields.iter().map(|f| {
        let field = &f.ident;
        let field_name = field.to_string();
        let value = f.get_field_value(use_self);
        // state is chosen outside
        my_quote!(#field_name => {
            #buf_ident.push_str(&#value.translate_obj_to_c(state, program)?)
        })
    });
    let items = my_quote![ #(#sers),* ];
    my_quote!(
    unsafe {
        let state = state.last_child()?;
        let key = state.key.as_str()?;
        match key {
            #items,
            _ => { unreachable!() },
        }
    }
    )
}

pub fn union_serialize_body(fields: &[FieldExt], use_self: bool) -> TokenStream {
    let buf_ident = syn::Ident::new("buf", Span::call_site());
    // FIXME: only serialize as first type
    let item_first = if let Some(f) = fields.first() {
        let field = &f.ident;
        let header = format!("{field}: ");
        let value = f.get_field_value(use_self);
        my_quote!(
            #buf_ident.push_str(#header);
            #buf_ident.push_str(&#value.serialize()?)
        )
    } else {
        my_quote!()
    };
    my_quote!(
    unsafe { #item_first }
    )
}

pub fn struct_deserialize_body(fields: &[FieldExt], unit: bool, named: bool) -> TokenStream {
    if unit {
        return my_quote!();
    }
    let de_ident = syn::Ident::new("de", Span::call_site());
    let desers = fields.iter().map(|f| {
        let field = &f.ident;
        let ty = f.ty;
        let header = format!("{field}:");
        let init = if f.is_phantom_data() {
            if cfg!(feature = "std") {
                my_quote!(::std::marker::PhantomData)
            } else {
                my_quote!(::core::marker::PhantomData)
            }
        } else {
            my_quote!({
                #de_ident.eat_token(#header)?;
                let val = <#ty>::deserialize(#de_ident)?;
                #de_ident.eat_token(", ")?;
                val
            })
        };
        if f.named {
            my_quote!(#field: #init)
        } else {
            my_quote!(#init)
        }
    });
    if named {
        my_quote![{ #(#desers),* }]
    } else {
        my_quote![( #(#desers),* )]
    }
}

pub fn struct_object_deserialize_body(fields: &[FieldExt], unit: bool, named: bool) -> TokenStream {
    if unit {
        return my_quote!();
    }
    let de_ident = syn::Ident::new("de", Span::call_site());
    let desers = fields.iter().map(|f| {
        let field = &f.ident;
        let field_name = field.to_string();
        let ty = f.ty;
        let header = format!("{field}:");
        let init = if f.is_phantom_data() {
            f.init_phantom(&field_name, ty)
        } else {
            my_quote!({
                #de_ident.eat_token(#header)?;
                let val = <#ty>::deserialize_obj(#de_ident, state.add_child(#field_name, std::any::type_name::<#ty>()).last_child_mut()?)?;
                #de_ident.eat_token(", ")?;
                val
            })
        };
        if f.named {
            my_quote!(#field: #init)
        } else {
            my_quote!(#init)
        }
    });
    if named {
        my_quote![{ #(#desers),* }]
    } else {
        my_quote![( #(#desers),* )]
    }
}

pub fn union_object_deserialize_body(fields: &[FieldExt]) -> TokenStream {
    let de_ident = syn::Ident::new("de", Span::call_site());
    let sers = fields.iter().map(|f| {
        let field = &f.ident;
        let field_name = field.to_string();
        let ty = &f.ty;
        my_quote!(#field_name => {
            Self { #field: <#ty>::deserialize_obj(#de_ident, state.add_child(#field_name, std::any::type_name::<#ty>()).last_child_mut()?)? }
        })
    });
    let items = my_quote![ #(#sers),* ];
    my_quote!(
    {
        let field = #de_ident.next_token_until(":")?;
        match field {
            #items
            _ => { unreachable!() },
        }
    })
}

pub fn union_deserialize_body(fields: &[FieldExt]) -> TokenStream {
    let de_ident = syn::Ident::new("de", Span::call_site());
    let sers = fields.iter().map(|f| {
        let field = &f.ident;
        let field_name = field.to_string();
        let ty = &f.ty;
        my_quote!(#field_name => {
            Self { #field: <#ty>::deserialize(#de_ident)? }
        })
    });
    let items = my_quote![ #(#sers),* ];
    my_quote!(
    {
        let field = #de_ident.next_token_until(":")?;
        match field {
            #items
            _ => { unreachable!() },
        }
    })
}

pub fn union_object_use_member(fields: &[FieldExt]) -> TokenStream {
    let use_member = fields.iter().map(|f| {
        let field = &f.ident;
        let field_name = field.to_string();
        let ty = &f.ty;
        let value = f.get_field_value(true);
        let crate_path = super::get_crate_path();
        // state should be revised
        my_quote!(#field_name => {
            let member_state = state.last_child_mut()?;
            if let hopper::FieldKey::Field(f) = &member_state.key {
                if member == f {
                    #crate_path::set_refine_suc(false);
                    return Ok(());
                } else {
                    state.clear();
                    #value = <#ty>::generate_new(state.add_child(#field_name, std::any::type_name::<#ty>()).last_child_mut()?)?;
                }
            }
        })
    });

    let items = my_quote![ #(#use_member),* ];
    my_quote!(
        match member.as_str() {
            #items
            _ => { unreachable!() },
        }
    )
}
