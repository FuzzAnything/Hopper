extern crate gimli;
extern crate object;

use crate::dwarf;

use gimli::ReaderOffset;
use std::collections::BTreeMap;

pub struct DwarfAnalyzer<R>
where
    R: gimli::Reader,
{
    dwarf: gimli::Dwarf<R>,
}

impl<R: gimli::Reader> DwarfAnalyzer<R> {
    pub fn new(dwarf: gimli::Dwarf<R>) -> Self {
        Self { dwarf }
    }

    pub fn parse(&mut self) -> Result<dwarf::Program, gimli::Error> {
        let mut program_units = vec![];

        // Iterate over the compilation units.
        let mut iter = self.dwarf.units();
        while let Some(header) = iter.next()? {
            println!(
                "Unit at <.debug_info+0x{:x}>",
                header.offset().as_debug_info_offset().unwrap().0.into_u64()
            );

            let mut type_table = BTreeMap::new();
            let mut fn_list = vec![];
            let mut var_list = vec![];
            let mut last_struct = None;
            let mut last_array = None;
            let mut unit_name = "None".to_string();
            let mut producer = "None".to_string();

            let unit = self.dwarf.unit(header)?;
            // Iterate over the Debugging Information Entries (DIEs) in the unit.
            let mut entries = unit.entries();
            // delta_depth:
            // 1 -> move to previous' children
            // 0 -> move to previous' sibling
            // -k -> move to previous' parent (depth = k)
            while let Some((delta_depth, entry)) = entries.next_dfs()? {
                let offset = entry.offset().0.into_u64();
                println!("<{}><{}> {}", delta_depth, offset, entry.tag());

                if delta_depth < 0 {
                    last_struct = None;
                    last_array = None;
                }
                match entry.tag() {
                    gimli::DW_TAG_compile_unit => {
                        unit_name = self
                            .dwarf
                            .attr_string(
                                &unit,
                                entry.attr_value(gimli::constants::DW_AT_name)?.unwrap(),
                            )?
                            .to_string_lossy()?
                            .to_string();

                        producer = self
                            .dwarf
                            .attr_string(
                                &unit,
                                entry.attr_value(gimli::constants::DW_AT_producer)?.unwrap(),
                            )?
                            .to_string_lossy()?
                            .to_string();
                    }
                    gimli::DW_TAG_file_type => {
                        unimplemented!();
                    }
                    gimli::DW_TAG_base_type => {
                        // self.print_attrs(&entry);
                        let name = self.dwarf.attr_string(
                            &unit,
                            entry.attr_value(gimli::constants::DW_AT_name)?.unwrap(),
                        )?;
                        let byte_size = entry
                            .attr_value(gimli::constants::DW_AT_byte_size)?
                            .unwrap()
                            .udata_value()
                            .unwrap() as usize;
                        let ty = dwarf::ArgType::from(name.to_string_lossy()?.as_ref(), byte_size);
                        type_table.insert(offset, ty);
                    }
                    gimli::DW_TAG_typedef => {
                        let name = self.dwarf.attr_string(
                            &unit,
                            entry.attr_value(gimli::constants::DW_AT_name)?.unwrap(),
                        )?;
                        // If it doesn't contain type attribute, it is a declaration instead of definition
                        let alias_type =
                            self.parse_type(entry)?.unwrap_or(dwarf::ArgType::Undefined);
                        let ty =
                            dwarf::ArgType::alias(name.to_string_lossy()?.as_ref(), alias_type);
                        type_table.insert(offset, ty);
                    }
                    gimli::DW_TAG_pointer_type => {
                        let dst_type = self.parse_type(entry)?.unwrap_or(dwarf::ArgType::Undefined);
                        let byte_size = entry
                            .attr_value(gimli::constants::DW_AT_byte_size)?
                            .unwrap()
                            .udata_value()
                            .unwrap() as usize;
                        let ty = dwarf::ArgType::pointer(dst_type, byte_size);
                        type_table.insert(offset, ty);
                    }
                    gimli::DW_TAG_const_type => {
                        let inner_type =
                            self.parse_type(entry)?.unwrap_or(dwarf::ArgType::Undefined);
                        let ty = dwarf::ArgType::constt(inner_type);
                        type_table.insert(offset, ty);
                    }
                    gimli::DW_TAG_structure_type => {
                        let name = self.dwarf.attr_string(
                            &unit,
                            entry.attr_value(gimli::constants::DW_AT_name)?.unwrap(),
                        )?;
                        if entry
                            .attr_value(gimli::constants::DW_AT_declaration)?
                            .is_some()
                        {
                            let ty = dwarf::ArgType::Decla(dwarf::DeclaType {
                                name: name.to_string_lossy()?.to_string(),
                            });
                            type_table.insert(offset, ty);
                        } else {
                            let byte_size = entry
                                .attr_value(gimli::constants::DW_AT_byte_size)?
                                .unwrap()
                                .udata_value()
                                .unwrap() as usize;
                            let ty = dwarf::ArgType::structt(
                                name.to_string_lossy()?.as_ref(),
                                byte_size,
                            );
                            type_table.insert(offset, ty);
                            last_struct = Some(offset);
                        }
                        // self.print_attrs(&entry)?;
                    }
                    gimli::DW_TAG_member => {
                        let name = self.dwarf.attr_string(
                            &unit,
                            entry.attr_value(gimli::constants::DW_AT_name)?.unwrap(),
                        )?;
                        let ty = self.parse_type(entry)?.unwrap_or(dwarf::ArgType::Void);
                        let location = entry
                            .attr_value(gimli::constants::DW_AT_data_member_location)?
                            .unwrap()
                            .udata_value()
                            .unwrap() as usize;
                        let member = dwarf::StructField {
                            name: name.to_string_lossy()?.to_string(),
                            ty: Box::new(ty),
                            location,
                        };
                        if let Some(index) = last_struct {
                            if let Some(dwarf::ArgType::Struct(structt)) =
                                type_table.get_mut(&index)
                            {
                                structt.fields.push(member);
                            }
                        }
                        // self.print_attrs(&entry);
                    }
                    gimli::DW_TAG_array_type => {
                        let ele_type = self.parse_type(entry)?.unwrap_or(dwarf::ArgType::Undefined);
                        let ty = dwarf::ArgType::array(ele_type);
                        type_table.insert(offset, ty);
                        last_array = Some(offset);
                    }
                    gimli::DW_TAG_subrange_type => {
                        if let Some(index) = last_array {
                            if let Some(t) = type_table.get_mut(&index) {
                                if let Some(attr) =
                                    entry.attr_value(gimli::constants::DW_AT_upper_bound)?
                                {
                                    if let Some(val) = attr.udata_value() {
                                        if let dwarf::ArgType::Array(arr) = t {
                                            arr.sub_range.push(val as usize + 1);
                                        }
                                    } else {
                                        unimplemented!();
                                    }
                                };
                            }
                        } else {
                            unimplemented!();
                        }
                    }
                    gimli::DW_TAG_variable => {
                        var_list.push(self.parse_variable(entry, &unit)?);
                    }
                    gimli::DW_TAG_subprogram
                    | gimli::DW_TAG_entry_point
                    | gimli::DW_TAG_inlined_subroutine => {
                        fn_list.push(self.parse_function(entry, &unit)?);
                    }
                    gimli::DW_TAG_formal_parameter => {
                        let arg_type = self.parse_type(entry)?.unwrap_or(dwarf::ArgType::Void);
                        if let Some(f) = fn_list.last_mut() {
                            f.arg_types.push(arg_type);
                        }
                    }
                    _ => {
                        self.print_attrs(entry)?;
                    }
                }
            }

            let program_unit = dwarf::ProgramUnit {
                name: unit_name,
                producer,
                type_table,
                fn_list,
                var_list,
            };
            program_units.push(program_unit);
        }

        Ok(dwarf::Program {
            units: program_units,
        })
    }

    fn parse_function(
        &self,
        entry: &gimli::read::DebuggingInformationEntry<R>,
        unit: &gimli::Unit<R>,
    ) -> Result<dwarf::Function, gimli::Error> {
        let name = self.dwarf.attr_string(
            unit,
            entry.attr_value(gimli::constants::DW_AT_name)?.unwrap(),
        )?;
        let ret_type = self.parse_type(entry)?.unwrap_or(dwarf::ArgType::Void);
        let external = match entry.attr_value(gimli::constants::DW_AT_external)? {
            Some(gimli::AttributeValue::Flag(flag)) => flag,
            _ => false,
        };

        let func = dwarf::Function {
            name: name.to_string_lossy()?.to_string(),
            ret_type,
            arg_types: vec![],
            external,
            position: self.parse_position(entry)?,
        };

        Ok(func)
    }

    fn parse_variable(
        &self,
        entry: &gimli::read::DebuggingInformationEntry<R>,
        unit: &gimli::Unit<R>,
    ) -> Result<dwarf::Variable, gimli::Error> {
        let name = self.dwarf.attr_string(
            unit,
            entry.attr_value(gimli::constants::DW_AT_name)?.unwrap(),
        )?;
        let ty = self.parse_type(entry)?.unwrap_or(dwarf::ArgType::Undefined);
        let external = match entry.attr_value(gimli::constants::DW_AT_external)? {
            Some(gimli::AttributeValue::Flag(flag)) => flag,
            _ => false,
        };

        let v = dwarf::Variable {
            name: name.to_string_lossy()?.to_string(),
            ty,
            external,
            position: self.parse_position(entry)?,
        };

        Ok(v)
    }

    fn parse_position(
        &self,
        entry: &gimli::read::DebuggingInformationEntry<R>,
    ) -> Result<dwarf::Position, gimli::Error> {
        let file_index = match entry
            .attr_value(gimli::constants::DW_AT_decl_file)?
            .unwrap()
        {
            gimli::AttributeValue::FileIndex(index) => index as usize,
            _ => 0,
        };
        let line = entry
            .attr_value(gimli::constants::DW_AT_decl_line)?
            .unwrap()
            .udata_value()
            .unwrap() as usize;
        let column = entry
            .attr_value(gimli::constants::DW_AT_decl_column)?
            .unwrap()
            .udata_value()
            .unwrap() as usize;
        Ok(dwarf::Position {
            file: file_index,
            line,
            column,
        })
    }

    fn parse_type(
        &self,
        entry: &gimli::read::DebuggingInformationEntry<R>,
    ) -> Result<Option<dwarf::ArgType>, gimli::Error> {
        let type_offset = entry.attr_value(gimli::constants::DW_AT_type)?;
        if type_offset.is_none() {
            return Ok(None);
        }
        match type_offset.unwrap() {
            gimli::AttributeValue::UnitRef(offset) => {
                Ok(Some(dwarf::ArgType::ref_as(offset.0.into_u64())))
            }
            _ => {
                unimplemented!();
                // Ok(Some(ir::ArgType::Undefined))
            }
        }
    }

    fn print_attrs(
        &self,
        entry: &gimli::read::DebuggingInformationEntry<R>,
    ) -> Result<(), gimli::Error> {
        let mut attrs = entry.attrs();

        while let Some(attr) = attrs.next()? {
            println!("   {}: {:?}", attr.name(), attr.value(),);
        }

        Ok(())
    }
}
