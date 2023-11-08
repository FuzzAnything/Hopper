use crate::field;
use crate::my_quote;

use proc_macro2::TokenStream;
use syn::{punctuated::Punctuated, Token};

/// Add implmentation of object's serde trait for struct types
pub fn serde_trait_for_struct(
    name: &syn::Ident,
    generics: &syn::Generics,
    _attrs: &[syn::Attribute],
    fields: &syn::Fields,
) -> TokenStream {
    let crate_path = super::get_crate_path();
    let (fields, named, unit) = field::convert_fields(fields);
    let ser_body = field::struct_serialize_body(&fields, true);
    let de_body = field::struct_deserialize_body(&fields, unit, named);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    my_quote! {
        impl #impl_generics #crate_path::Serialize for #name #ty_generics #where_clause {
            fn serialize(&self) -> eyre::Result<String> {
                let mut buf = String::new();
                buf.push_str("{ ");
                #ser_body;
                buf.push_str(" }");
                Ok(buf)
            }
        }
        impl #impl_generics #crate_path::Deserialize for #name #ty_generics #where_clause {
            fn deserialize(de: &mut #crate_path::Deserializer) -> eyre::Result<Self> {
                de.eat_token("{")?;
                let val = #name #de_body;
                de.eat_token("}")?;
                Ok(val)
            }
        }
    }
}

pub fn object_serde_trait_for_struct(
    name: &syn::Ident,
    generics: &syn::Generics,
    _attrs: &[syn::Attribute],
    fields: &syn::Fields,
) -> TokenStream {
    let crate_path = super::get_crate_path();
    let (fields, named, unit) = field::convert_fields(fields);
    let ser_obj_body = field::struct_object_serialize_body(&fields, true);
    let trans_obj_body = field::struct_object_translate_body(&fields, true);
    let de_obj_body = field::struct_object_deserialize_body(&fields, unit, named);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    my_quote! {
        impl #impl_generics #crate_path::ObjectSerialize for #name #ty_generics #where_clause {
            fn serialize_obj(&self, state: &#crate_path::ObjectState) -> eyre::Result<String> {
                let mut buf = String::new();
                buf.push_str("{ ");
                #ser_obj_body;
                buf.push_str(" }");
                Ok(buf)
            }
        }
        impl #impl_generics #crate_path::ObjectDeserialize for #name #ty_generics #where_clause {
            fn deserialize_obj(de: &mut #crate_path::Deserializer, state: &mut #crate_path::ObjectState) -> eyre::Result<Self> {
                de.eat_token("{")?;
                let val = #name #de_obj_body;
                de.eat_token("}")?;
                Ok(val)
            }
        }
        impl #impl_generics #crate_path::ObjectTranslate for #name #ty_generics #where_clause {
            fn translate_obj_to_c(&self, state: &#crate_path::ObjectState, program: &#crate_path::FuzzProgram) -> eyre::Result<String> {
                let mut buf = String::new();
                buf.push_str("{ ");
                #trans_obj_body;
                buf.push_str(" }");
                Ok(buf)
            }
        }
    }
}

pub fn serde_trait_for_union(
    name: &syn::Ident,
    generics: &syn::Generics,
    _attrs: &[syn::Attribute],
    fields: &syn::FieldsNamed,
) -> TokenStream {
    let crate_path = super::get_crate_path();
    let fields = field::convert_field_list(Some(&fields.named), true);
    let ser_body = field::union_serialize_body(&fields, true);
    let de_body = field::union_deserialize_body(&fields);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    my_quote! {
        impl #impl_generics #crate_path::Serialize for #name #ty_generics #where_clause {
            fn serialize(&self) -> eyre::Result<String> {
                let mut buf = String::new();
                buf.push_str("{ ");
                #ser_body;
                buf.push_str(" }");
                Ok(buf)
            }
        }
        impl #impl_generics #crate_path::Deserialize for #name #ty_generics #where_clause {
            fn deserialize(de: &mut #crate_path::Deserializer) -> eyre::Result<Self> {
                de.eat_token("{")?;
                let val = #de_body;
                de.trim_start();
                de.eat_token("}")?;
                Ok(val)
            }
        }
    }
}

pub fn object_serde_trait_for_union(
    name: &syn::Ident,
    generics: &syn::Generics,
    _attrs: &[syn::Attribute],
    fields: &syn::FieldsNamed,
) -> TokenStream {
    let crate_path = super::get_crate_path();
    let fields = field::convert_field_list(Some(&fields.named), true);
    let ser_obj_body = field::union_object_serialize_body(&fields, true);
    let trans_obj_body = field::union_object_translate_body(&fields, true);
    let de_obj_body = field::union_object_deserialize_body(&fields);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    my_quote! {
        impl #impl_generics #crate_path::ObjectSerialize for #name #ty_generics #where_clause {
            fn serialize_obj(&self, state: &#crate_path::ObjectState) -> eyre::Result<String> {
                let mut buf = String::new();
                buf.push_str("{ ");
                #ser_obj_body;
                buf.push_str(" }");
                Ok(buf)
            }
        }
        impl #impl_generics #crate_path::ObjectDeserialize for #name #ty_generics #where_clause {
            fn deserialize_obj(de: &mut #crate_path::Deserializer, state: &mut #crate_path::ObjectState) -> eyre::Result<Self> {
                state.is_union = true;
                de.eat_token("{")?;
                let val = #de_obj_body;
                de.trim_start();
                de.eat_token("}")?;
                Ok(val)
            }
        }
        impl #impl_generics #crate_path::ObjectTranslate for #name #ty_generics #where_clause {
            fn translate_obj_to_c(&self, state: &#crate_path::ObjectState, program: &#crate_path::FuzzProgram) -> eyre::Result<String> {
                let mut buf = String::new();
                buf.push_str("{ ");
                #trans_obj_body;
                buf.push_str(" }");
                Ok(buf)
            }
        }
    }
}

pub fn serde_trait_for_enum(
    name: &syn::Ident,
    generics: &syn::Generics,
    _attrs: &[syn::Attribute],
    variants: &Punctuated<syn::Variant, Token![,]>,
) -> TokenStream {
    let crate_path = super::get_crate_path();
    let ser_impls = variants.iter().map(|v| {
        let key = &v.ident;
        let key_name = key.to_string();
        let fields = &v.fields;
        if fields.is_empty() {
            my_quote!(Self::#key => {
                Ok(format!("{}$", #key_name))
            })
        } else {
            let (fields, named, _) = field::convert_fields(fields);
            let fields_ser = field::struct_serialize_body(&fields, false);
            let field_keys = field::list_field_keys(&fields, named);
            my_quote!(Self::#key #field_keys => {
                let mut buf = String::new();
                buf.push_str(#key_name);
                buf.push_str("${ ");
                #fields_ser
                buf.push_str(" }");
                Ok(buf)
            })
        }
    });
    let ser_impls = my_quote![ #(#ser_impls),* ];
    let de_impls = variants.iter().map(|v| {
        let key = &v.ident;
        let key_name = key.to_string();
        let fields = &v.fields;
        if fields.is_empty() {
            my_quote!(#key_name => Ok(Self::#key))
        } else {
            let (fields, named, unit) = field::convert_fields(fields);
            let de_obj_body = field::struct_deserialize_body(&fields, unit, named);
            my_quote!(#key_name => {
                de.eat_token("{")?;
                let val = Self::#key #de_obj_body;
                de.trim_start();
                de.eat_token("}")?;
                Ok(val)
            })
        }
    });
    let de_impls = my_quote![ #(#de_impls),* ];
  
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    my_quote! {
        impl #impl_generics #crate_path::Serialize for #name #ty_generics #where_clause {
            fn serialize(&self) -> eyre::Result<String> {
                match self {
                    #ser_impls,
                    _ => { unreachable!() },
                }
            }
        }
        impl #impl_generics #crate_path::Deserialize for #name #ty_generics #where_clause {
            fn deserialize(de: &mut #crate_path::Deserializer) -> eyre::Result<Self> {
                let key = de.next_token_until("$")?;
                match key {
                    #de_impls,
                    _ => { eyre::bail!("fail to deserialize: {}", de.buf) },
                }
            }
        }
    }
}

pub fn object_serde_trait_for_enum(
    name: &syn::Ident,
    generics: &syn::Generics,
    _attrs: &[syn::Attribute],
    variants: &Punctuated<syn::Variant, Token![,]>,
) -> TokenStream {
    let crate_path = super::get_crate_path();
    let ser_obj_impls = variants.iter().map(|v| {
        let key = &v.ident;
        let key_name = key.to_string();
        let fields = &v.fields;
        if fields.is_empty() {
            my_quote!(Self::#key => {
                Ok(format!("{}$", #key_name))
            })
        } else {
            let (fields, named, _) = field::convert_fields(fields);
            let fields_ser = field::struct_object_serialize_body(&fields, false);
            let field_keys = field::list_field_keys(&fields, named);
            my_quote!(Self::#key #field_keys => {
                let mut buf = String::new();
                buf.push_str(#key_name);
                buf.push_str("${ ");
                #fields_ser
                buf.push_str(" }");
                Ok(buf)
            })
        }
    });
    let ser_obj_impls = my_quote![ #(#ser_obj_impls),* ];
    let de_obj_impls = variants.iter().map(|v| {
        let key = &v.ident;
        let key_name = key.to_string();
        let fields = &v.fields;
        if fields.is_empty() {
            my_quote!(#key_name => Ok(Self::#key))
        } else {
            let (fields, named, unit) = field::convert_fields(fields);
            let de_obj_body = field::struct_object_deserialize_body(&fields, unit, named);
            my_quote!(#key_name => {
                de.eat_token("{")?;
                let val = Self::#key #de_obj_body;
                de.trim_start();
                de.eat_token("}")?;
                Ok(val)
            })
        }
    });
    let de_obj_impls = my_quote![ #(#de_obj_impls),* ];
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    my_quote! {
        impl #impl_generics #crate_path::ObjectSerialize for #name #ty_generics #where_clause {
            fn serialize_obj(&self, state: &#crate_path::ObjectState) -> eyre::Result<String> {
                match self {
                    #ser_obj_impls,
                    _ => { unreachable!() },
                }
            }
        }
        impl #impl_generics #crate_path::ObjectDeserialize for #name #ty_generics #where_clause {
            fn deserialize_obj(de: &mut #crate_path::Deserializer, state: &mut #crate_path::ObjectState) -> eyre::Result<Self> {
                let key = de.next_token_until("$")?;
                match key {
                    #de_obj_impls,
                    _ => { unreachable!() },
                }
            }
        }
    }
}

pub fn kind_trait_for_enum(
    name: &syn::Ident,
    generics: &syn::Generics,
    _attrs: &[syn::Attribute],
    variants: &Punctuated<syn::Variant, Token![,]>,
) -> TokenStream {
    let kind_impls = variants.iter().map(|v| {
        let key = &v.ident;
        let key_name = key.to_string();
        let fields = &v.fields;
        if fields.is_empty() {
            my_quote!(Self::#key => #key_name)
        } else {
            let (_, named, _) = field::convert_fields(fields);
            if named {
                my_quote!(Self::#key {..} => #key_name)
            } else {
                my_quote!(Self::#key(_) => #key_name)
            }
        }
    });
    let kind_impls = my_quote![ #(#kind_impls),* ];
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    my_quote! {
        impl #impl_generics EnumKind for #name #ty_generics #where_clause {
            fn kind(&self) -> &'static str {
                match self {
                    #kind_impls,
                    _ => { unreachable!() },
                }
            }
        }
    }
}
