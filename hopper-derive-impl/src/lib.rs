pub mod field;
pub mod folder;
pub mod format;
pub mod func_hook;
pub mod object;
pub mod visitor;
pub mod serde;

#[macro_use]
extern crate quote;
use proc_macro2::TokenStream;
use syn::{fold::Fold, visit::Visit};

pub const ENABLE_SET_FN_POINTER: bool = enable_fn_pointer();
pub const DEFAULT_FN_POINTER_PREFIX: &str = fn_pointer_name_prefix();

#[macro_export]
macro_rules! my_quote {
    ($($t:tt)*) => (quote_spanned!(proc_macro2::Span::call_site() => $($t)*))
}

pub fn derive_bindings(content: &str) -> TokenStream {
    let syntax = syn::parse_file(content).expect("Unable to parse file");

    let mut folder = folder::FuzzFolder::default();
    let replaced_syntax = folder.fold_file(syntax);

    let mut fuzz_visitor = visitor::FuzzVisitor::default();
    fuzz_visitor.visit_file(&replaced_syntax);

    let callbacks = fuzz_visitor.generate_callbacks();

    let result = my_quote!(
        #callbacks

        #replaced_syntax

        #fuzz_visitor
    );

    result
}

static mut USE_IN_COMPILER: bool = false;

pub fn set_compiler_env() {
    unsafe {
        USE_IN_COMPILER = true;
    }
}

pub fn get_crate_path() -> syn::Path {
    if cfg!(feature = "use_crate") && ! unsafe { USE_IN_COMPILER } {
        syn::parse_quote!(crate)
    } else {
        syn::parse_quote!(::hopper)
    }
}

const fn enable_fn_pointer() -> bool {
    option_env!("HOPPER_DISABLE_FN_POINTER").is_none()
}

const fn fn_pointer_name_prefix() -> &'static str {
    if let Some(v) = option_env!("HOPPER_FUNCTION_POINTER_PREFIX") {
        v
    } else {
        "GENERATED_hopper_callback_"
    }
}

fn is_packed_struct(attrs: &[syn::Attribute]) -> bool {
    let attrs_tokens = my_quote!(#(#attrs)*, );
    let attrs = attrs_tokens.to_string();
    attrs.contains("packed")
}
