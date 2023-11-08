//! TODO: Extract information from debugging information
//! It needs to reverse function signatures and custom data structures.
//! We just put some simple codes and do not implement it,
//! so it is not used in Hopper, too.

#![allow(dead_code)]

mod analyzer;
mod arg_type;
mod function;
mod position;
mod program;
mod variable;

use object::{Object, ObjectSection};
use std::{borrow, fs::File, path::Path};

pub use analyzer::*;
pub use arg_type::*;
pub use function::*;
pub use position::*;
pub use program::*;
pub use variable::*;

pub fn analyze_dwarf(library: &Path) -> Result<Program, gimli::Error> {
    let file = File::open(library).expect("fail to open library file");
    let mmap = unsafe { memmap::Mmap::map(&file).unwrap() };
    let object = &object::File::parse(&*mmap).expect("fail to parse object");

    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    // Load a section and return as `Cow<[u8]>`.
    let load_section = |id: gimli::SectionId| -> Result<borrow::Cow<[u8]>, gimli::Error> {
        match object.section_by_name(id.name()) {
            Some(ref section) => Ok(section
                .uncompressed_data()
                .unwrap_or_else(|_| borrow::Cow::Borrowed(&[][..]))),
            None => Ok(borrow::Cow::Borrowed(&[][..])),
        }
    };

    // Load all of the sections.
    let dwarf_cow = gimli::Dwarf::load(&load_section)?;

    // Borrow a `Cow<[u8]>` to create an `EndianSlice`.
    let borrow_section: &dyn for<'a> Fn(
        &'a borrow::Cow<[u8]>,
    ) -> gimli::EndianSlice<'a, gimli::RunTimeEndian> =
        &|section| gimli::EndianSlice::new(section, endian);

    // Create `EndianSlice`s for all of the sections.
    let dwarf = dwarf_cow.borrow(&borrow_section);
    let mut analyzer = DwarfAnalyzer::new(dwarf);

    analyzer.parse()
}
