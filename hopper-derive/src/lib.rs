//!# A custom dervie implementation for `#[derive(Hopper)]`, which is used in Hopper Fuzzer.
//!
//!blabla...

#![crate_type = "proc-macro"]
#![recursion_limit = "192"]
extern crate proc_macro;
extern crate proc_macro2;
extern crate syn;
#[macro_use]
extern crate quote;
use hopper_derive_impl::*;

use proc_macro::TokenStream;
use syn::visit::Visit;
use syn::ItemFn;

#[proc_macro_attribute]
pub fn fuzz_all(_metadata: TokenStream, input: TokenStream) -> TokenStream {
    let input: syn::ItemMod = syn::parse(input).expect("Couldn't parse item mod");
    let mut fuzz_vistor = visitor::FuzzVisitor::default().set_mod_ident(input.ident.clone());
    fuzz_vistor.visit_item_mod(&input);

    let result = my_quote!(
     #input
     #fuzz_vistor
    );
    result.into()
}

#[proc_macro_derive(Fuzz, attributes(Fuzz))]
pub fn derive_fuzz(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).expect("Couldn't parse item");
    let result = match ast.data {
        syn::Data::Enum(ref e) => object::object_trait_for_enum(&ast.ident, &ast.generics, &ast.attrs, &e.variants),
        syn::Data::Struct(ref s) => object::object_trait_for_struct(&ast.ident, &ast.generics, &ast.attrs, &s.fields),
        syn::Data::Union(ref u) => object::object_trait_for_union(&ast.ident, &ast.generics, &ast.attrs, &u.fields),
    };
    result.into()
}

#[proc_macro_attribute]
pub fn fuzz(_metadata: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn: ItemFn = syn::parse(input).expect("Couldn't parse function signature");
    let ctor_hook = func_hook::add_func_hook(
        &format!("fn_{}", &input_fn.sig.ident),
        &vec![input_fn.sig.clone()],
        &[],
        &[],
    );

    let result = my_quote!(
        #input_fn
        #ctor_hook
    );

    result.into()
}

#[proc_macro_derive(Serde, attributes(Serde))]
pub fn derive_serde(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).expect("Couldn't parse item");
    let result = match ast.data {
        syn::Data::Enum(ref e) => serde::serde_trait_for_enum(&ast.ident, &ast.generics, &ast.attrs, &e.variants),
        syn::Data::Struct(ref s) => serde::serde_trait_for_struct(&ast.ident, &ast.generics, &ast.attrs, &s.fields),
        syn::Data::Union(ref u) => serde::serde_trait_for_union(&ast.ident, &ast.generics, &ast.attrs, &u.fields),
    };
    result.into()
}

#[proc_macro_derive(ObjectSerde, attributes(ObjectSerde))]
pub fn derive_obj_serde(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).expect("Couldn't parse item");
    let result = match ast.data {
        syn::Data::Enum(ref e) => serde::serde_trait_for_enum(&ast.ident, &ast.generics, &ast.attrs, &e.variants),
        syn::Data::Struct(ref s) => serde::serde_trait_for_struct(&ast.ident, &ast.generics, &ast.attrs, &s.fields),
        syn::Data::Union(ref u) => serde::serde_trait_for_union(&ast.ident, &ast.generics, &ast.attrs, &u.fields),
    };
    result.into()
}

#[proc_macro_derive(EnumKind, attributes(EnumKind))]
pub fn derive_enum_kind(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).expect("Couldn't parse item");
    let result = match ast.data {
        syn::Data::Enum(ref e) => serde::kind_trait_for_enum(&ast.ident, &ast.generics, &ast.attrs, &e.variants),
        _ => unreachable!()
    };
    result.into()
}