//! ctor: https://github.com/mmastrac/rust-ctor/blob/master/ctor/src/lib.rs

use crate::my_quote;
use proc_macro2::{Ident, Span, TokenStream};
use syn::{parse_quote, spanned::Spanned, ItemStruct, ItemType, Signature};

pub const MAX_SIG_ARG_LEN: usize = 12;

#[cfg(feature = "link_hook")]
pub fn add_func_hook<'ast>(
    hook_name: &str,
    sigs: &[Signature],
    structs: &[&'ast ItemStruct],
    alias: &[&'ast ItemType],
) -> TokenStream {
    let linkme_ident = Ident::new(&format!("{}___hopper_gadget", hook_name), Span::call_site());

    let type_gadgets = convert_struct_to_type_gadgets(structs);
    let func_gadgets = convert_sig_to_func_gadgets(sigs);
    let strcut_extra = add_custom_type_extra_info(structs, alias);
    let crate_path = super::get_crate_path();
    my_quote!(
        #[::linkme::distributed_slice(#crate_path::link_hook::HOPPER_FN_GADGET_PROVIDERS)]
        fn #linkme_ident (gadgets: &mut #crate_path::ProgramGadgets) {
            #(#func_gadgets)*
            #(#type_gadgets)*
            #(#strcut_extra)*
            gadgets.build_graph();
        }
    )
}

#[cfg(feature = "ctor_hook")]
pub fn add_func_hook<'ast>(
    hook_name: &str,
    sigs: &[Signature],
    structs: &[&'ast ItemStruct],
    alias: &[&'ast ItemType],
) -> TokenStream {
    let ctor_ident = Ident::new(
        &format!("{hook_name}___hopper_ctor___ctor"),
        Span::call_site(),
    );

    let type_gadgets = convert_struct_to_type_gadgets(structs);
    let func_gadgets = convert_sig_to_func_gadgets(sigs);
    let strcut_extra = add_custom_type_extra_info(structs, alias);
    let crate_path = super::get_crate_path();
    my_quote!(
        #[used]
        #[allow(non_upper_case_globals)]
        #[doc(hidden)]
        #[cfg_attr(any(target_os = "linux", target_os = "android"), link_section = ".init_array")]
        #[cfg_attr(target_os = "freebsd", link_section = ".init_array")]
        #[cfg_attr(target_os = "netbsd", link_section = ".init_array")]
        #[cfg_attr(target_os = "openbsd", link_section = ".init_array")]
        #[cfg_attr(target_os = "dragonfly", link_section = ".init_array")]
        #[cfg_attr(target_os = "illumos", link_section = ".init_array")]
        #[cfg_attr(any(target_os = "macos", target_os = "ios"), link_section = "__DATA,__mod_init_func")]
        #[cfg_attr(windows, link_section = ".CRT$XCU")]
        static #ctor_ident
        :
        unsafe extern "C" fn() =
        {
            unsafe extern "C" fn #ctor_ident() {
                let gadgets = #crate_path::global_gadgets::get_mut_instance();
                #(#func_gadgets)*
                #(#type_gadgets)*
                #(#strcut_extra)*
                gadgets.build_graph();
            }
            #ctor_ident
        }
        ;
    )
}

fn convert_struct_to_type_gadgets(structs: &[&'_ ItemStruct]) -> Vec<TokenStream> {
    structs
        .iter()
        .map(|&sig| {
            let ty = &sig.ident;
            my_quote!(
                gadgets.add_type_with_pointer::<#ty>();
            )
        })
        .collect()
}


fn convert_sig_to_func_gadgets(sigs: &[Signature]) -> Vec<TokenStream> {
    sigs.iter()
        .map(|sig| {
            let fn_name = &sig.ident;
            // avoid too many args / name starts with '_' / return '!'
            if sig.inputs.len() > MAX_SIG_ARG_LEN || fn_name.to_string().starts_with('_') {
                return my_quote!();
            }
            if let syn::ReturnType::Type(_, ref ty) = sig.output {
                if matches!(ty.as_ref(), syn::Type::Never(_)) {
                    return my_quote!();
                }
            }

            match convert_sig_to_fn_type(sig) {
                Ok((fn_type, extra_info)) => my_quote!(
                    gadgets.add_function(stringify!(#fn_name), &(#fn_name as #fn_type), #extra_info);
                ),
                Err(errors) => errors.iter().map(syn::parse::Error::to_compile_error).collect(),
            }
        })
        .collect()
}

fn add_custom_type_extra_info(
    structs: &[&'_ ItemStruct],
    alias: &[&'_ ItemType],
) -> Vec<TokenStream> {
    let alias_idents: Vec<String> = alias.iter().map(|item| item.ident.to_string()).collect();
    let mut tokens = vec![];
    for stru in structs {
        let stru_ident = stru.ident.to_string();
        let (fields, _named, _unit) = super::field::convert_fields(&stru.fields, false);
        for f in &fields {
            let ty = f.ty;
            let ty_alias = format_type(ty);
            // only add alias type for pointer
            if !ty_alias.starts_with("std")
                && (alias_idents.contains(&ty_alias) || is_alias_pointer(&ty_alias, &alias_idents))
            {
                let mut f_ident = f.ident.to_string();
                f_ident.push_str("@hopper_harness::");
                f_ident.push_str(&stru_ident);
                tokens.push(my_quote!(
                    gadgets.add_field_alias_type::<#ty>(#f_ident, #ty_alias);
                ))
            }
        }
    }
    tokens
}

fn is_alias_pointer(type_name: &str, alias_idents: &[String]) -> bool {
    if let Some(t) = type_name.strip_prefix("hopper::runtime::") {
        if let Some(t) = t.strip_prefix("FuzzConstPointer<") {
            let inner = t.strip_suffix('>').unwrap();
            return alias_idents.iter().any(|s| s == inner);
        }
        if let Some(t) = t.strip_prefix("FuzzMutPointer<") {
            let inner = t.strip_suffix('>').unwrap();
            return alias_idents.iter().any(|s| s == inner);
        }
    }
    false
}

fn convert_sig_to_fn_type(
    sig: &Signature,
) -> Result<(syn::TypeBareFn, TokenStream), Vec<syn::parse::Error>> {
    let mut args: syn::punctuated::Punctuated<syn::BareFnArg, syn::token::Comma> =
        syn::punctuated::Punctuated::new();
    let mut arg_idents = vec![];
    let mut alias_arg_types = vec![];
    let mut alias_ret_type = my_quote!(None);
    let mut errors = vec![];
    sig.inputs.iter().for_each(|arg| match *arg {
        syn::FnArg::Typed(syn::PatType {
            ref pat, ref ty, ..
        }) => {
            let ident: Ident = parse_quote!(#pat);
            arg_idents.push(ident.to_string());
            args.push(parse_quote!(_: #ty));
            let ty_str = format_type(ty);
            alias_arg_types.push(my_quote!(#ty_str));
        }
        _ => {
            errors.push(syn::parse::Error::new(
                arg.span(),
                "unsupported kind of function argument",
            ));
        }
    });

    if let syn::ReturnType::Type(_, ref ty) = sig.output {
        let ty_str = format_type(ty);
        alias_ret_type = my_quote!(Some(#ty_str));
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let fn_type = syn::TypeBareFn {
        lifetimes: None,
        unsafety: sig.unsafety,
        abi: sig.abi.clone(),
        fn_token: <syn::Token![fn]>::default(),
        paren_token: syn::token::Paren::default(),
        inputs: args,
        variadic: sig.variadic.clone(),
        output: sig.output.clone(),
    };
    let extra_info = my_quote!(&[#(#arg_idents),*], &[#(#alias_arg_types),*], #alias_ret_type);
    Ok((fn_type, extra_info))
}

pub fn format_type(ty: &syn::Type) -> String {
    let mut ty_str = my_quote!(#ty).to_string();
    ty_str.retain(|c| !c.is_whitespace());
    ty_str
        .replace("FuzzMutPointer<", "hopper::runtime::FuzzMutPointer<")
        .replace("FuzzConstPointer<", "hopper::runtime::FuzzConstPointer<")
        .replace(
            "::hopper::FuzzMutPointer::",
            "hopper::runtime::FuzzMutPointer",
        )
        .replace(
            "::hopper::FuzzConstPointer::",
            "hopper::runtime::FuzzConstPointer",
        )
        .replace("::hopper::FuzzVoid", "hopper::runtime::FuzzVoid")
        .replace("::std", "std")
}
