use hopper_derive::Serde;

#[derive(Debug, Default, Clone, Serde)]
pub struct FuncRole {
    // the function will init argument
    pub init_arg: bool,
    // the function will free argument
    pub free_arg: bool,
}

impl FuncRole {
    /// Check if the function's return can be used as arguments or fields
    #[inline]
    pub fn can_used_as_arg(&self) -> bool {
        !self.free_arg
    }
}

#[inline]
pub fn filter_init_func(f_name: &str) -> bool {
    super::filter_function_constraint_with(f_name, |fc| fc.is_success() && fc.role.init_arg && !fc.role.free_arg)
}

#[inline]
pub fn filter_free_func(f_name: &str) -> bool {
    super::filter_function_constraint_with(f_name, |fc| fc.role.free_arg)
}