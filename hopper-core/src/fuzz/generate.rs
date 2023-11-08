use eyre::Context;

use crate::{fuzz::rng, runtime::*, utils};

impl FuzzProgram {
    /// Generate random program,
    pub fn generate_program(
        candidates: Option<&Vec<String>>,
        enable_fail: bool,
    ) -> eyre::Result<FuzzProgram> {
        let f_name = if let Some(f_name) = crate::config::get_config().func_target {
            f_name
        } else {
            // Choose function target from gadgets with the pattern defined in configuration.
            // Even the functions are marked as can_success:false, we still generate program for them.
            // We hope that those generation found some success programs.
            let f = |f_name| {
                if enable_fail {
                    crate::filter_function_constraint_with(f_name, |fc| !fc.internal)
                } else {
                    crate::filter_function(f_name)
                }
            };
            if let Some(list) = candidates {
                rng::choose_iter(list.iter().filter(|f_name| f(f_name))).ok_or_else(|| {
                    eyre::eyre!("function gadget is empty with candidates {:?}", list)
                })?
            } else {
                rng::choose_iter(
                    global_gadgets::get_instance()
                        .functions
                        .keys()
                        .filter(|f_name| f(f_name)),
                )
                .map(|f_name| f_name.as_str())
                .ok_or_else(|| eyre::eyre!("function gadget is empty"))?
            }
        };

        Self::generate_program_for_func(f_name)
    }

    /// Generate random program for function `f`
    pub fn generate_program_for_func_randomly(f_name: &str) -> eyre::Result<FuzzProgram> {
        // create an empty program
        let mut program: FuzzProgram = Default::default();
        program.save_mutate_state();
        let mut call = CallStmt::generate_new(&mut program, CallStmt::TARGET, f_name, 0)
            .with_context(|| format!("fail to generate call `{f_name}`"))?;
        // only track target function
        call.track_cov = true;
        let _stmt = program.append_stmt(call);
        program.check_ref_use()?;
        program
            .refine_program()
            .with_context(|| program.serialize_all().unwrap())?;
        Ok(program)
    }

    /// Generate program for function `f`
    pub fn generate_program_for_func(f_name: &str) -> eyre::Result<FuzzProgram> {
        #[cfg(feature = "slices")]
        if let Some(p) = Self::generate_program_for_func_by_slices(f_name)? {
            return Ok(p);
        }
        Self::generate_program_for_func_randomly(f_name)
    }
}

/// Choose any function that provide specific type.
pub fn find_func_with_return_type(type_name: &str, alias_type_name: &str) -> Option<&'static str> {
    let gadgets = global_gadgets::get_instance();
    crate::log!(
        trace,
        "find return for type `{type_name} / {alias_type_name}`"
    );

    let is_void_ptr = utils::is_void_pointer(type_name);
    // stupid case: alias void type to another type named void
    if is_void_ptr && (alias_type_name.contains("void") || alias_type_name.contains("Void")) {
        return None;
    }
    // try alias type first
    // try different pointers for inner type
    if let Some(inner) = utils::get_pointer_inner(alias_type_name) {
        let mut_ptr = utils::mut_pointer_type(inner);
        let mut_iter: &[&str] = gadgets
            .ret_graph
            .get(mut_ptr.as_str())
            .map_or(&[], |l| l.as_slice());
        let const_ptr = utils::const_pointer_type(inner);
        let const_iter: &[&str] = gadgets
            .ret_graph
            .get(const_ptr.as_str())
            .map_or(&[], |l| l.as_slice());
        let iter = mut_iter.iter().chain(const_iter);
        return choose_provider(iter);
    }

    // alias type may not starts with `FuzzMutPointer` or `FuzzConstPointer`.
    // alias type is a pointer itself.
    if let Some(fs) = gadgets.ret_graph.get(alias_type_name) {
        let iter = fs.iter();
        return choose_provider(iter);
    }

    // try type_name if it is not void pointer
    if is_void_ptr {
        return None;
    }
    if let Some(inner) = utils::get_pointer_inner(type_name) {
        let mut_ptr = utils::mut_pointer_type(inner);
        let mut_iter: &[&str] = gadgets
            .ret_graph
            .get(mut_ptr.as_str())
            .map_or(&[], |l| l.as_slice());
        let const_ptr = utils::const_pointer_type(inner);
        let const_iter: &[&str] = gadgets
            .ret_graph
            .get(const_ptr.as_str())
            .map_or(&[], |l| l.as_slice());
        let iter = mut_iter.iter().chain(const_iter);
        return choose_provider(iter);
    }

    None
}

/// Choose one item randomly in providers
fn choose_provider<'a, I>(iter: I) -> Option<&'static str>
where
    I: Iterator<Item = &'a &'static str> + Clone + std::fmt::Debug,
{
    let iter = iter.filter(|f_name| {
        crate::filter_function_constraint_with(f_name, |fc| fc.can_used_as_arg())
    });
    if let Some(provider) = rng::choose_iter(iter) {
        crate::log!(trace, "choose provider: {provider}");
        return Some(provider);
    }
    crate::log!(trace, "can not find any provider");
    None
}
