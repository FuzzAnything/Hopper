use std::collections::BTreeMap;

use proc_macro2::{Ident, Span, TokenStream};
use quote::{ToTokens, TokenStreamExt};
use syn::{
    visit::{self, Visit},
    ForeignItemFn, ItemEnum, ItemFn, ItemForeignMod, ItemStruct, ItemType, ItemUnion, ReturnType,
    Signature, Token, TypeBareFn, TypePath,
};

use crate::my_quote;
use crate::object;
use crate::{func_hook::*, ENABLE_SET_FN_POINTER};

#[derive(Default)]
pub struct FuzzVisitor<'ast> {
    mod_ident: Option<Ident>,
    functions: Vec<Signature>,
    structs: Vec<&'ast ItemStruct>,
    enums: Vec<&'ast ItemEnum>,
    unions: Vec<&'ast ItemUnion>,
    type_alias: Vec<&'ast ItemType>,
    extern_mark: Option<&'ast ItemForeignMod>,
    excluded_type: Vec<String>,
    // TypeBareFn does not implement `Default`, so we cannot use hashmap.
    callbacks: BTreeMap<String, TypeBareFn>,
}

impl<'ast> FuzzVisitor<'ast> {
    pub fn set_mod_ident(mut self, mod_ident: Ident) -> Self {
        self.mod_ident = Some(mod_ident);
        self
    }

    fn hook_name(&self) -> String {
        if let Some(mod_name) = &self.mod_ident {
            format!("mod_{mod_name}")
        } else {
            "file_bindings".to_string()
        }
    }

    fn hook_func_pointer_type(&mut self, path: &TypePath) {
        if !ENABLE_SET_FN_POINTER {
            return;
        }
        if let Some(fn_ty) = super::folder::get_fn_type_in_option(path) {
            if fn_ty.variadic.is_none() {
                let mut identifier =
                    fn_ty
                        .inputs
                        .iter()
                        .fold(String::new(), |mut identifier, arg_ty| {
                            identifier.push_str(&arg_ty.ty.to_token_stream().to_string());
                            identifier.push(';');
                            identifier
                        });
                identifier.push_str("->");
                identifier.push_str(&fn_ty.output.to_token_stream().to_string());
                self.callbacks.insert(identifier, fn_ty.clone());
            }
        }
    }

    fn add_func_hook_to_tokens(&self, tokens: &mut TokenStream) {
        let funcs: Vec<Signature> = self
            .functions
            .iter()
            .filter(|f| {
                // check if the signature contain excluded types
                let name = f.ident.to_string();
                let syntax = my_quote!(#f);
                let syntax = syntax.to_string();
                if name.starts_with("__") {
                    println!("cargo:warning=`{}` includes `__`", &syntax);
                    return false;
                }
                for ty in &self.excluded_type {
                    if syntax.contains(ty) {
                        println!("cargo:warning=`{}` use excluded type: {}", &syntax, ty);
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        let ts = add_func_hook(&self.hook_name(), &funcs, &self.structs, &self.type_alias);
        tokens.extend(ts);
    }

    fn add_structs_to_tokens(&self, tokens: &mut TokenStream) {
        for &stru in &self.structs {
            let ts = object::object_trait_for_struct(
                &stru.ident,
                &stru.generics,
                &stru.attrs,
                &stru.fields,
            );
            tokens.extend(ts);
        }
    }

    fn add_enums_to_tokens(&self, tokens: &mut TokenStream) {
        for &enu in &self.enums {
            let ts =
                object::object_trait_for_enum(&enu.ident, &enu.generics, &enu.attrs, &enu.variants);
            tokens.extend(ts);
        }
    }

    fn add_unions_to_tokens(&self, tokens: &mut TokenStream) {
        for &un in &self.unions {
            let ts = object::object_trait_for_union(&un.ident, &un.generics, &un.attrs, &un.fields);
            tokens.extend(ts);
        }
    }

    pub fn generate_callbacks(&mut self) -> TokenStream {
        let callbacks = self.callbacks.values().enumerate().map(|(i, f_raw)| {
            let unsafety = &f_raw.unsafety;
            let abi = &f_raw.abi;
            let fn_token = &f_raw.fn_token;
            let mut fn_name_str = String::from("GENERATED_hopper_callback_");
            fn_name_str.push_str(&i.to_string());
            println!("cargo:warning=generate callback {fn_name_str}: {}", f_raw.to_token_stream());
            let fn_name_tokens = fn_name_str.parse::<proc_macro2::TokenStream>().unwrap();
            let lifetimes = &f_raw.lifetimes;
            let inputs = &f_raw.inputs;
            let output = &f_raw.output; 
            let fn_body_tokens = if let ReturnType::Type(_, ty) = output { 
                // Callback returns non-void
                let crate_path = super::get_crate_path();
                let ret_ty = ty.to_token_stream();
                // Here we make a meaningless state to please `generate_new`.
                let mut body = my_quote!(
                    use #crate_path::ObjGenerate;
                    #crate_path::set_pilot_det(true);
                    let ret = #ret_ty::generate_new(&mut #crate_path::ObjectState::root("", "")).expect("failed to generate objects in callback");
                    #crate_path::set_pilot_det(false);
                    ret
                );
                if let syn::Type::Path(path) = ty.as_ref() {
                    if super::folder::get_fn_type_in_option(path).is_some() {
                        body = my_quote!(None)
                    }
                }
                body
            } else {
                // Callback returns void.
                my_quote!( () )
            };
            let sig_tokens = my_quote!(
                #unsafety #abi #fn_token #fn_name_tokens #lifetimes (#inputs) #output
            );
            let sig: Signature = syn::parse2(sig_tokens.clone()).expect("failed to parse function signature");
            self.functions.push(sig);
            let callback = my_quote!(
                #[no_mangle]
                #[allow(unused_variables)]
                pub #sig_tokens {
                    #fn_body_tokens
                }
            );

            callback
        });

        my_quote!( #(#callbacks)* )
    }
}

impl<'ast> Visit<'ast> for FuzzVisitor<'ast> {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        let attrs = &node.attrs;
        let attrs_tokens = my_quote!(#(#attrs)*, );
        let attrs = attrs_tokens.to_string();
        let ident = node.ident.to_string();
        if ident == "__BindgenBitfieldUnit" {
            // ignore implement for __BindgenBitfieldUnit
        }
        // avoid adding struct without clone
        else if !attrs.contains("Clone") {
            println!(
                "cargo:warning={} has not clone attribute! {}",
                &ident, attrs
            );
            self.excluded_type.push(ident);
        } else {
            self.structs.push(node);
        }
        visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast ItemEnum) {
        self.enums.push(node);
        visit::visit_item_enum(self, node);
    }

    fn visit_item_union(&mut self, node: &'ast ItemUnion) {
        self.unions.push(node);
        visit::visit_item_union(self, node);
    }

    fn visit_item_type(&mut self, node: &'ast ItemType) {
        self.type_alias.push(node);
        visit::visit_item_type(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast ItemForeignMod) {
        self.extern_mark = Some(node);
        visit::visit_item_foreign_mod(self, node);
        self.extern_mark = None;
    }

    fn visit_foreign_item_fn(&mut self, node: &'ast ForeignItemFn) {
        if check_pub_vis(&node.vis) {
            if let Some(mark) = self.extern_mark {
                let mut sig = node.sig.clone();
                sig.abi = Some(mark.abi.clone());
                sig.unsafety = Some(Default::default());
                self.functions.push(sig);
            }
        }
        visit::visit_foreign_item_fn(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if check_pub_vis(&node.vis) {
            self.functions.push(node.sig.clone());
        }
        visit::visit_item_fn(self, node);
    }

    fn visit_type_path(&mut self, node: &'ast TypePath) {
        self.hook_func_pointer_type(node);
        visit::visit_type_path(self, node);
    }
}

fn check_pub_vis(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

impl<'ast> ToTokens for FuzzVisitor<'ast> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        if let Some(mod_name) = &self.mod_ident {
            let mod_kw = <Token!(mod)>::default();
            mod_kw.to_tokens(tokens);
            let fuzz_mod = Ident::new(&format!("{mod_name}_hopper_generated"), Span::call_site());
            tokens.append(fuzz_mod);

            let brace = syn::token::Brace::default();
            brace.surround(tokens, |tokens| {
                tokens.extend(my_quote!(use super::#mod_name::*;));

                self.add_structs_to_tokens(tokens);
                self.add_enums_to_tokens(tokens);
                self.add_unions_to_tokens(tokens);
                self.add_func_hook_to_tokens(tokens);
            });
        } else {
            self.add_structs_to_tokens(tokens);
            self.add_enums_to_tokens(tokens);
            self.add_unions_to_tokens(tokens);
            self.add_func_hook_to_tokens(tokens);
        }
    }
}
