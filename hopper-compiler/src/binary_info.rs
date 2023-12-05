use goblin::Object;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct BinaryInfo {
    // library type: elf or pe
    pub lib_type: &'static str,
    // all names in the symbol table
    pub str_list: Vec<String>,
    // exported API in the symbol table
    pub func_list: Vec<FuncInfo>,
    // needed libraries
    pub needed: Vec<String>
}

#[derive(Debug)]
pub struct FuncInfo {
    pub name: String,
    pub addr: u64,
    pub size: u64,
}

impl BinaryInfo {
    pub fn parse(path: &Path) -> eyre::Result<Self> {
        let file = fs::File::open(path)?;
        let f = unsafe { memmap::MmapOptions::new().map(&file)? };
        let buf = f.as_ref();
        let result = Object::parse(buf).expect("fail to parse object");
        let lib_type;
        let mut str_list = vec![];
        let mut func_list = vec![];
        let mut needed = vec![];
        match result {
            Object::Elf(elf) => {
                lib_type = "elf";
                for sym in &elf.dynsyms {
                    let name = elf.dynstrtab.get_at(sym.st_name).unwrap();
                    if sym.st_shndx == 0 && !name.is_empty() {
                        str_list.push(name.to_string());
                    }
                    if sym.is_function()
                        && sym.st_bind() == 1
                        && sym.st_value > 0
                        && sym.st_size > 0
                    {
                        func_list.push(FuncInfo {
                            name: name.to_string(),
                            addr: sym.st_value,
                            size: sym.st_size,
                        })
                    }
                }
                for sym in &elf.syms {
                    let name = elf.strtab.get_at(sym.st_name).unwrap();
                    if sym.st_shndx == 0 && !name.is_empty() {
                        str_list.push(name.to_string());
                    }
                    // Global: st_bind == 1
                    if sym.is_function()
                        && sym.st_bind() == 1
                        && sym.st_value > 0
                        && sym.st_size > 0
                    {
                        func_list.push(FuncInfo {
                            name: name.to_string(),
                            addr: sym.st_value,
                            size: sym.st_size,
                        })
                    }
                }
                if let Some(dy) = elf.dynamic.as_ref() {
                    for name in dy.get_libraries(&elf.dynstrtab) {
                        needed.push(name.to_string());
                    }
                }
                
            }
            Object::PE(pe) => {
                lib_type = "pe";
                let strtab = pe.header.coff_header.strings(buf)?;
                str_list = strtab.to_vec()?.iter().map(|s| s.to_string()).collect();

                let symbol_table = pe.header.coff_header.symbols(buf)?;
                let symbol_size = pe.header.coff_header.number_of_symbol_table as usize;
                let virtual_address = pe.sections[0].virtual_address as u64;
                let image_base = pe.image_base as u64;
                let mut index: usize = 0;
                while index != symbol_size {
                    if let Some(mut sym) = symbol_table.get(index) {
                        if sym.1.typ == 0x20 {
                            // function
                            let offset = sym.1.value as u64;
                            let addr: u64 = image_base + virtual_address + offset;
                            let name = if let Some(name) = &sym.0 {
                                name
                            } else {
                                // strtab miss 4 bytes.
                                // https://github.com/m4b/goblin/issues/171
                                sym.1.set_name_offset(sym.1.name_offset().unwrap() - 4);
                                sym.1.name(&strtab).unwrap()
                            };
                            func_list.push(FuncInfo {
                                name: name.to_string(),
                                addr,
                                size: 0,
                            });
                        }
                    }
                    index += 1;
                }
            }
            _ => eyre::bail!(format!("unimplemented!: {result:?}")),
        }
        // sort func list by address
        func_list.sort_by(|a, b| a.addr.cmp(&b.addr));
        func_list.dedup_by_key(|f| f.addr);
        str_list.dedup();
        Ok(Self {
            lib_type,
            str_list,
            func_list,
            needed,
        })
    }

    /// Check if string tables contain specific strings
    pub fn contain_func(&self, func: &str) -> bool {
        self.str_list.iter().any(|name| {
            if name == func || name.starts_with(&format!("{func}@")) {
                return true;
            }
            #[cfg(target_os = "windows")]
            if name.starts_with(&format!("__impl_{func}")) {
                return true;
            }
            false
        })
    }

    /// Get function's address range in the binary
    pub fn get_function_addr_range(&self, name: &str) -> Option<(u64, u64)> {
        if let Some(pos) = self.func_list.iter().position(|f| f.name == name) {
            let f = &self.func_list[pos];
            let cur_addr = f.addr;
            if pos == self.func_list.len() - 1 || f.size > 0 {
                // register_frame_ctor should + 0x10 in the end
                return Some((cur_addr, cur_addr + f.size));
            } else {
                return Some((cur_addr, self.func_list[pos + 1].addr));
            }
        }
        None
    }

    /// Function's range that should not be patched in the binary
    /// used for e9patch
    pub fn list_exclude_patch_range(&self) -> Vec<(u64, u64)> {
        let mut blacklist = HashSet::new();
        if self.lib_type == "pe" {
            blacklist.extend(PE_DEFAULT_BLACK_LIST);
        }
        let optional = std::env::var("HOPPER_E9_BLACK_LIST");
        if let Ok(list) = &optional {
            for f in list.split(',') {
                blacklist.insert(f);
            }
        }
        let mut ranges = vec![];
        for name in blacklist {
            if let Some(range) = self.get_function_addr_range(name) {
                ranges.push(range);
            }
        }
        ranges
    }
}

/// Save function list to disk
pub fn save_func_list(func_list: &[FuncInfo], output: &Path) -> eyre::Result<()> {
    use std::io::Write;
    let file = output.join("func_list");
    log::info!(
        "save function list in the binary into {}",
        file.to_string_lossy()
    );
    let mut f = std::fs::File::create(file)?;
    for func in func_list {
        writeln!(f, "{}", func.name)?;
    }
    Ok(())
}

const PE_DEFAULT_BLACK_LIST: &[&str] = &[
    "_CRT_INIT",
    "__DllMainCRTStartup",
    "DllMainCRTStartup",
    "__dyn_tls_dtor",
    "__dyn_tls_init",
    "_execute_onexit_table",
    "_pei386_runtime_relocator",
    "__mingw_TLScallback",
    "__mingw_GetSectionCount",
    "_ValidateImageBase.part.0",
    "_register_onexit_function",
    "ValidateImageBase",
    "DllEntryPoint",
    "DllMain",
    "__do_global_dtors",
    "__gcc_deregister_frame",
    "__mingwthr_run_key_dtors.part.0",
    "__security_init_cookie",
];

#[test]
fn test_parse_zlib() {
    let zlib_path = std::path::Path::new("/usr/lib64/libz.so");
    if zlib_path.exists() {
        let ret = BinaryInfo::parse(zlib_path).unwrap();
        println!("ret: {ret:?}");
    }
}
