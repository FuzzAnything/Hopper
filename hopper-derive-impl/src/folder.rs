use syn::{
    fold::{self, Fold},
    Type, TypeBareFn,
};

use crate::my_quote;

pub struct FuzzFolder {
    replace_ptr: bool,
}

impl Default for FuzzFolder {
    fn default() -> Self {
        Self { replace_ptr: true }
    }
}

impl Fold for FuzzFolder {
    fn fold_type(&mut self, node: Type) -> Type {
        if !self.replace_ptr {
            return fold::fold_type(self, node);
        }
        match node {
            Type::Ptr(ptr) => {
                let crate_path = super::get_crate_path();
                let inner = self.fold_type(*ptr.elem);
                if ptr.mutability.is_some() {
                    Type::Verbatim(my_quote!(
                        #crate_path::FuzzMutPointer::<#inner>
                    ))
                } else {
                    Type::Verbatim(my_quote!(
                        #crate_path::FuzzConstPointer::<#inner>
                    ))
                }
            }
            Type::Path(ref path) => {
                if check_void_type(path) {
                    let crate_path = super::get_crate_path();
                    Type::Verbatim(my_quote!(
                        #crate_path::FuzzVoid
                    ))
                } else if check_fn_ptr_path(path) {
                    let crate_path = super::get_crate_path();
                    Type::Verbatim(my_quote!(
                        #crate_path::FuzzFrozenPointer::<#path>
                    ))
                } else if let Some(ty) = check_bitfield_type(path) {
                    ty
                } else {
                    fold::fold_type(self, node)
                }
            }
            _ => fold::fold_type(self, node),
        }
    }

    fn fold_item_impl(&mut self, i: syn::ItemImpl) -> syn::ItemImpl {
        let ty = &i.self_ty;
        let ty = my_quote!(#ty).to_string();
        // ignore
        if ty.starts_with("__BindgenBitfieldUnit") {
            return i;
        }
        if ty.starts_with("__IncompleteArrayField") {
            println!("cargo:warning=item: {ty:?}, disable replace ptr");
            self.replace_ptr = false;
            let ret = fold::fold_item_impl(self, i);
            self.replace_ptr = true;
            ret
        } else {
            fold::fold_item_impl(self, i)
        }
    }
}

const VOID_PATH: [&str; 4] = ["std", "os", "raw", "c_void"];

fn check_void_type(path: &syn::TypePath) -> bool {
    let it = path.path.segments.iter();
    it.zip(VOID_PATH.iter())
        .all(|(seg, ident)| seg.ident == ident)
}

fn check_bitfield_type(path: &syn::TypePath) -> Option<Type> {
    let mut it = path.path.segments.iter();
    if let Some(seg) = it.next() {
        if seg.ident == "__BindgenBitfieldUnit" {
            let crate_path = super::get_crate_path();
            let arg = &seg.arguments;
            return Some(Type::Verbatim(my_quote!(
                #crate_path::HopperBindgenBitfieldUnit::#arg
            )));
        }
    }
    None
}

fn check_fn_ptr_path(path: &syn::TypePath) -> bool {
    if let Some(fn_ty) = get_fn_type_in_option(path) {
        // We don't want the number of arguments in a function pointer to exceed MAX_SIG_ARG_LEN either.
        if fn_ty.inputs.len() > crate::func_hook::MAX_SIG_ARG_LEN {
            return true;
        }
    }
    false
}

pub fn get_fn_type_in_option(path: &syn::TypePath) -> Option<&TypeBareFn> {
    let mut it = path.path.segments.iter();
    let generic_args = it
        .next()
        .and_then(|seg| {
            if seg.ident == "std" || seg.ident == "core" {
                it.next()
            } else {
                None
            }
        })
        .and_then(|seg| {
            if seg.ident == "option" {
                it.next()
            } else {
                None
            }
        })
        .and_then(|seg| {
            if seg.ident == "Option" {
                Some(&seg.arguments)
            } else {
                None
            }
        });
    if let Some(syn::PathArguments::AngleBracketed(params)) = generic_args {
        if let syn::GenericArgument::Type(syn::Type::BareFn(fn_ty)) =
            params.args.iter().next().unwrap()
        {
            return Some(fn_ty);
        }
    }
    None
}
