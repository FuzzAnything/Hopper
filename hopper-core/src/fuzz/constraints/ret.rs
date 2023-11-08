use hopper_derive::Serde;

use crate::{global_gadgets, utils};

#[derive(Debug, Default, Clone, Serde)]
pub struct RetType {
    // return is opaque pointer
    pub is_opaque: bool,
    // return is malloc'ed statically
    pub is_static: bool,
    // return pointer is unwriteable
    pub is_unwriteable: bool,
    // return pointer is partial opaque
    pub is_partial_opaque: bool,
    // the API is both consumer and producer of certain pointers.  e.g.  A* = f(A*)
    pub both_cosumer_and_producer: bool,
}

impl RetType {
    /// Check if the function's return can be used as arguments or fields
    #[inline]
    pub fn can_used_as_arg(&self) -> bool {
        !self.is_unwriteable
            && ((self.is_opaque && !self.both_cosumer_and_producer)
                || (!self.is_opaque && !self.is_static))
    }

    /// Infer function return's kind: opaque or recursion
    pub fn infer(&mut self, f_name: &str) -> eyre::Result<()> {
        let fg = global_gadgets::get_instance().get_func_gadget(f_name)?;
        if let Some(ret_type) = fg.ret_type {
            if let Some(ret_inner) = utils::get_pointer_inner(ret_type) {
                if utils::is_opaque_type(ret_inner) {
                    self.is_opaque = true;
                }
                let mut alias_ret_inner = ret_inner;
                if let Some(alias_ret_type) = fg.alias_ret_type {
                    if let Some(inner) = utils::get_pointer_inner(alias_ret_type) {
                        alias_ret_inner = inner;
                    }
                }
                for (t, at) in fg.arg_types.iter().zip(fg.alias_arg_types.iter()) {
                    let mut t = t;
                    let mut r = ret_inner;
                    // avoid recursion
                    if utils::is_void_pointer(t) {
                        t = at;
                        r = alias_ret_inner;
                    }
                    if let Some(arg_inner) = utils::get_pointer_inner(t) {
                        if arg_inner == r {
                            self.both_cosumer_and_producer = true;
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
