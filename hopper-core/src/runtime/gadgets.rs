//! Gadgets for fuzzing
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
};

use crate::{runtime::*, utils, ObjGenerate};

/// Gadgets for generate programs.
///
/// It includes functions, struct types, and so on.
pub struct ProgramGadgets {
    /// Function gadgets used for create calls.
    pub functions: BTreeMap<String, FnGadget>,
    /// Type gadgets used for create objects by `generate_new` or `deserialize` ...
    pub types: BTreeMap<String, FuzzObjectBuilder>,

    /// Ret Graph: mapping return type -> function
    pub ret_graph: HashMap<&'static str, Vec<&'static str>>,
    /// Arg Graph: mapping arg type -> (function, index)
    pub arg_graph: HashMap<&'static str, Vec<(&'static str, usize)>>,

    /// Opaque types
    pub opaque_types: HashSet<String>,

    /// Type alias mapping of struct fields
    pub field_alias: HashMap<(&'static str, &'static str), &'static str>,

    /// Ty Strings
    pub ty_strings: HashSet<String>,
}

/// Function Gadget
#[derive(Debug, Clone)]
pub struct FnGadget {
    pub f_name: &'static str,
    pub f: &'static dyn FnFuzzable,
    pub arg_idents: &'static [&'static str],
    pub arg_types: &'static [&'static str],
    pub ret_type: Option<&'static str>,
    pub alias_arg_types: Vec<&'static str>,
    pub alias_ret_type: Option<&'static str>,
}

impl Default for ProgramGadgets {
    fn default() -> Self {
        let mut gadgets = Self {
            functions: BTreeMap::new(),
            types: BTreeMap::new(),
            ret_graph: HashMap::new(),
            arg_graph: HashMap::new(),
            opaque_types: HashSet::new(),
            field_alias: HashMap::new(),
            ty_strings: HashSet::new(),
        };
        gadgets.init_primitive_type();
        gadgets
    }
}

impl ProgramGadgets {
    /// Init type gadgets for primitive types
    ///
    /// These types could only used in pointers or cast cases.
    pub fn init_primitive_type(&mut self) {
        macro_rules! add_primitive_type {
            ( $($name:ident),* ) => {
                $(
                    self.add_type_with_pointer::<$name>();
                )*
            }
        }
        add_primitive_type!(u8, i8, u16, i16, u32, i32, u64, i64, f32, f64, char, bool, RetVoid);
    }

    /// Check gadgets are valid or not
    pub fn check(&self) -> eyre::Result<()> {
        if self.functions.is_empty() {
            eyre::bail!("Can't find any function for gadgets!");
        }
        if self.types.is_empty() {
            eyre::bail!("Can't find any type for gadgets!");
        }
        read_existing_opaue()?;
        Ok(())
    }

    /// Add function gadget
    ///
    /// We also will add types they used to type gadgets map.
    pub fn add_function(
        &mut self,
        f_name: &'static str,
        f: &'static dyn FnFuzzable,
        arg_idents: &'static [&'static str],
        alias_arg_types: &'static [&'static str],
        alias_ret_type: Option<&'static str>,
    ) {
        // ignore func starts with "_"
        if f_name.starts_with('_') {
            return;
        }
        f.add_type_gadgets(self);
        let fg = FnGadget {
            f_name,
            f,
            arg_idents,
            arg_types: f.get_arg_type_names().leak(),
            ret_type: f.get_ret_type_name(),
            alias_arg_types: Vec::from(alias_arg_types),
            alias_ret_type,
        };
        self.functions.insert(f_name.to_string(), fg);
    }

    /// Get function caller by their function name
    pub fn get_func_caller(&self, func_name: &str) -> eyre::Result<&dyn FnFuzzable> {
        self.functions
            .get(func_name)
            .map(|fg| fg.f)
            .ok_or_else(|| eyre::eyre!("Can't find any function caller for `{}`", func_name))
    }

    /// Get function gadget by their function name
    pub fn get_func_gadget(&self, func_name: &str) -> eyre::Result<&FnGadget> {
        self.functions
            .get(func_name)
            .ok_or_else(|| eyre::eyre!("Can't find any function gadget for `{}`", func_name))
    }

    /// Add opaque type
    pub fn add_opaque_type(&mut self, ty: &str) {
        crate::log_new_opaque(ty);
        self.opaque_types.insert(ty.to_string());
    }

    /// Add type gadget
    pub fn add_type<T: ObjFuzzable + ObjGenerate + ObjectDeserialize>(&mut self) {
        let type_name = std::any::type_name::<T>();
        if !self.types.contains_key(type_name) {
            self.types
                .insert(type_name.to_string(), FuzzTypeHolder::<T>::builder());
            T::add_fields_to_gadgets(self);
        }
    }

    pub fn add_type_with_pointer<T: ObjFuzzable + ObjGenerate + ObjectDeserialize>(&mut self) {
        self.add_type::<T>();
        let type_name = std::any::type_name::<T>();
        if !utils::is_pointer_type(type_name) {
            self.types.insert(
                utils::const_pointer_type(type_name),
                FuzzTypeHolder::<FuzzConstPointer<T>>::builder(),
            );
            self.types.insert(
                utils::mut_pointer_type(type_name),
                FuzzTypeHolder::<FuzzMutPointer<T>>::builder(),
            );
            T::add_fields_to_gadgets(self);
        }
    }

    /// Add alias type for type inside struct
    /// ident: field_name@sturct_name
    pub fn add_field_alias_type<T: ObjFuzzable>(
        &mut self,
        ident: &'static str,
        alias_type: &'static str,
    ) {
        let type_name = std::any::type_name::<T>();
        let key = (ident, type_name);
        if let Some(v) = self.field_alias.get_mut(&key) {
            // if the alias has conflict
            if alias_type != *v {
                *v = "-";
            }
            return;
        }
        self.field_alias.insert(key, alias_type);
    }

    /// Get field's alias type
    /// ident: field_name@struct_name
    pub fn get_field_alias_type<'a>(&self, ident: &str, type_name: &'a str) -> &'a str {
        if let Some(ty) = self.field_alias.get(&(ident, type_name)) {
            // if there exists any conflict, return type without alias
            if *ty != "-" {
                return ty;
            }
        }
        type_name
    }

    /// Get object builder
    pub fn get_object_builder<'a>(
        &'a self,
        type_name: &str,
    ) -> eyre::Result<&'a FuzzObjectBuilder> {
        self.types
            .get(type_name)
            .ok_or_else(|| eyre::eyre!("Can't find any type gadget for `{}`", type_name,))
    }

    /// Build some graphs for relationship between types and functions
    pub fn build_graph(&mut self) {
        // crate::log!(trace, "build graph");
        // should be done both in fuzzer and harness
        for (type_name, builder) in &self.types {
            if builder.is_opaque() {
                self.opaque_types.insert(type_name.to_string());
            }
        }
        self.opaque_types.insert("hopper::runtime::FuzzVoid".into());

        // ignore build graph in harness
        if let Ok(path) = std::env::current_exe() {
            if path.as_os_str().to_str().unwrap().ends_with("harness") {
                return;
            }
        }
        self.build_arg_and_ret_graph();
    }

    /// Build graph for function's arg and return
    pub fn build_arg_and_ret_graph(&mut self) {
        self.ret_graph.clear();
        for fg in self.functions.values() {
            if let Some(ret_type) = fg.ret_type {
                let list = self.ret_graph.entry(ret_type).or_default();
                list.push(fg.f_name);
            }
            if let Some(ret_type) = fg.alias_ret_type {
                let list = self.ret_graph.entry(ret_type).or_default();
                list.push(fg.f_name);
            }
        }
        self.arg_graph.clear();
        for fg in self.functions.values() {
            for i in 0..fg.alias_arg_types.len() {
                let arg_type = fg.arg_types[i];
                let alias_type = fg.alias_arg_types[i];
                if utils::is_pointer_type(arg_type) {
                    let list = self.arg_graph.entry(arg_type).or_default();
                    list.push((fg.f_name, i));
                    let list = self.arg_graph.entry(alias_type).or_default();
                    list.push((fg.f_name, i));
                }
            }
        }
    }

    pub fn save_gadgets_to_file(&self) -> eyre::Result<()> {
        if cfg!(test) {
            return Ok(());
        }
        use std::io::Write;
        let path = crate::config::output_file_path("misc/gadgets.log");
        let mut f = std::fs::File::create(path)?;
        writeln!(f, "functions:")?;
        for fg in &self.functions {
            writeln!(f, "{fg:?}")?;
        }
        writeln!(f, "types:")?;
        writeln!(f, "{:?}", self.types.keys().collect::<Vec<&String>>())?;
        writeln!(f, "opaques:")?;
        writeln!(f, "{:?}", self.opaque_types)?;

        writeln!(f, "field alias:").unwrap();
        writeln!(f, "{:?}", self.field_alias)?;

        writeln!(f, "ret graph:").unwrap();
        for r in &self.ret_graph {
            writeln!(f, "{r:?}")?;
        }
        Ok(())
    }

    pub fn init_ty_strings(&mut self) {
        self.types.keys().for_each(|ty| {
            self.ty_strings.insert(ty.clone());
        });
    }
}

impl fmt::Debug for ProgramGadgets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("ProgramGadgets");
        s.field("functions", &self.functions.keys());
        s.field("types", &self.types.keys());
        s.finish()
    }
}

/// Hook for adding gadgets at runtime by ctor
#[cfg(feature = "ctor_hook")]
pub mod ctor_hook {
    use super::ProgramGadgets;

    /// Global variable for gadgets that will fill data at ctor
    pub static mut GADGETS: Option<ProgramGadgets> = None;

    // We assume gadgets can't be mutated while running, therefore it is safe to share between threads.
    unsafe impl Sync for ProgramGadgets {}
}

/// Hook for adding gadgets using linkme approach
///
// Use linkme to find all functions that handle gadgets during compilation and linking
// It's more secure and efficient that won't call ctor multiple times.
#[cfg(feature = "link_hook")]
pub mod link_hook {
    use super::ProgramGadgets;
    use linkme::distributed_slice;
    use once_cell::sync::OnceCell;

    #[distributed_slice]
    pub static HOPPER_FN_GADGET_PROVIDERS: [fn(&mut ProgramGadgets)] = [..];

    #[distributed_slice(HOPPER_FN_GADGET_PROVIDERS)]
    fn test_link_hook_works(_g: &mut ProgramGadgets) {
        // Just for test and print some logs.
        crate::log!(info, "link hook works!");
    }

    pub static GADGETS_INSTANCE: OnceCell<ProgramGadgets> = OnceCell::new();
}

/// Gadegets used as global variables. It can be accessed at anywhere.
pub mod global_gadgets {
    use crate::ProgramGadgets;

    /// Get gadgets instance
    ///
    /// ProgramGadgets are initialized at this function.
    #[cfg(feature = "link_hook")]
    pub fn get_instance() -> &'static ProgramGadgets {
        use super::link_hook;
        link_hook::GADGETS_INSTANCE.get_or_init(|| {
            let mut gadgets = ProgramGadgets::default();
            for provider in link_hook::HOPPER_FN_GADGET_PROVIDERS {
                provider(&mut gadgets);
            }
            gadgets
        })
    }

    /// Get gadgets instance
    ///
    /// ProgramGadgets are initialized at ctor. This function just used for fetch the data.
    /// It can be called once in ctor feature since we take and return the ownershop directly.
    #[cfg(feature = "ctor_hook")]
    pub fn get_instance() -> &'static ProgramGadgets {
        use super::ctor_hook;
        unsafe {
            if ctor_hook::GADGETS.is_none() {
                ctor_hook::GADGETS = Some(ProgramGadgets::default());
            }
            ctor_hook::GADGETS.as_ref().unwrap()
        }
    }

    #[cfg(feature = "ctor_hook")]
    pub fn get_mut_instance() -> &'static mut ProgramGadgets {
        use super::ctor_hook;
        unsafe {
            if ctor_hook::GADGETS.is_none() {
                ctor_hook::GADGETS = Some(ProgramGadgets::default());
            }
            ctor_hook::GADGETS.as_mut().unwrap()
        }
    }
}

#[test]
fn test_gadgets() {
    // gadgets_test_setup::test_setup();
    let instance = global_gadgets::get_instance();
    assert!(instance.check().is_ok());
    let func = instance.get_func_caller("func_add").unwrap();
    assert_eq!(func.get_arg_type_names(), &["u8", "u8"]);
    assert_eq!(func.get_ret_type_name(), Some("u8"));
    assert!(instance.get_object_builder("u64").is_ok());
}

// logging for constraint updates
pub fn log_new_opaque(content: &str) {
    #[cfg(test)]
    {
        print!("log opaque types: {content}");
    }
    #[cfg(not(test))]
    {
        use std::io::prelude::*;
        let path = crate::config::output_file_path("misc/opaque.log");
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .unwrap();
        writeln!(f, "{content}").unwrap();
    }
}

pub fn read_existing_opaue() -> eyre::Result<()> {
    if cfg!(test) {
        return Ok(());
    }
    let path = crate::config::output_file_path("misc/opaque.log");
    if !path.exists() {
        return Ok(());
    }
    use std::io::prelude::*;
    let buf = std::fs::read(path)?;
    for line in buf.lines() {
        let ty= line?;
        if !ty.is_empty() {
            global_gadgets::get_mut_instance().opaque_types.insert(ty);
        }
    }
    Ok(())
}
