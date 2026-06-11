use std::ops::Range;

use super::abbrev::AbbrevTable;
use super::constants::*;
use super::cursor::Cursor;
use crate::error::{Error, Result};

/// Index of a compilation unit within a `Dwarf`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CuId(pub usize);

/// For 32-bit DWARF 5 compile units: unit_length(4) + version(2) +
/// unit_type(1) + address_size(1) + debug_abbrev_offset(4).
const HEADER_SIZE: usize = 12;

pub struct CompileUnit {
    id: CuId,
    range: Range<usize>,
    version: u16,
    address_size: u8,
    abbrev: AbbrevTable,
    addr_base: u32,
    str_offsets_base: u32,
    rnglists_base: u32,
}

impl CompileUnit {
    pub fn id(&self) -> CuId {
        self.id
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn address_size(&self) -> u8 {
        self.address_size
    }

    pub(crate) fn range(&self) -> &Range<usize> {
        &self.range
    }

    /// Offset of this unit's header within `.debug_info`.
    pub fn offset(&self) -> usize {
        self.range.start
    }

    pub(crate) fn root_offset(&self) -> usize {
        self.range.start + HEADER_SIZE
    }

    pub(crate) fn abbrev_table(&self) -> &AbbrevTable {
        &self.abbrev
    }

    pub fn addr_base(&self) -> u32 {
        self.addr_base
    }

    pub fn str_offsets_base(&self) -> u32 {
        self.str_offsets_base
    }

    pub fn rnglists_base(&self) -> u32 {
        self.rnglists_base
    }
}

pub(crate) fn parse_units(debug_info: &[u8], debug_abbrev: &[u8]) -> Result<Vec<CompileUnit>> {
    let mut units = Vec::new();
    let mut cursor = Cursor::new(debug_info);

    while !cursor.is_finished() {
        let start = cursor.position();

        // Compile unit header, DWARF 5 §7.5.1.1. A unit_length of 0xffffffff
        // would signal the 64-bit format, which we don't support.
        let unit_length = cursor.u32();
        if unit_length == 0xffff_ffff {
            return Err(Error::new("64-bit DWARF is not supported"));
        }
        let version = cursor.u16();
        if version != 5 {
            return Err(Error::new("Only DWARF version 5 is supported"));
        }
        let unit_type = cursor.u8();
        if u64::from(unit_type) != DW_UT_compile {
            return Err(Error::new("Only DWARF full compile units are supported"));
        }
        let address_size = cursor.u8();
        if address_size != 8 {
            return Err(Error::new("Only 64-bit addresses are supported"));
        }
        let debug_abbrev_offset = cursor.u32();

        let end = start + 4 + unit_length as usize;
        let abbrev = AbbrevTable::parse(debug_abbrev, debug_abbrev_offset as usize);

        let bases = read_root_bases(debug_info, &abbrev, start + HEADER_SIZE);
        units.push(CompileUnit {
            id: CuId(units.len()),
            range: start..end,
            version,
            address_size,
            abbrev,
            addr_base: bases.0,
            str_offsets_base: bases.1,
            rnglists_base: bases.2,
        });

        cursor = Cursor::at(debug_info, end);
    }

    Ok(units)
}

/// Read the section-offset bases the unit needs to resolve indexed forms,
/// straight from the root DIE without a full `Dwarf` context.
fn read_root_bases(debug_info: &[u8], abbrev: &AbbrevTable, root_offset: usize) -> (u32, u32, u32) {
    let mut cursor = Cursor::at(debug_info, root_offset);
    let code = cursor.uleb128();
    let Some(root) = abbrev.get(code) else {
        return (0, 0, 0);
    };

    let (mut addr_base, mut str_offsets_base, mut rnglists_base) = (0, 0, 0);
    for spec in &root.attrs {
        let value_offset = cursor.position();
        if spec.attr == DW_AT_addr_base {
            addr_base = Cursor::at(debug_info, value_offset).u32();
        } else if spec.attr == DW_AT_str_offsets_base {
            str_offsets_base = Cursor::at(debug_info, value_offset).u32();
        } else if spec.attr == DW_AT_rnglists_base {
            rnglists_base = Cursor::at(debug_info, value_offset).u32();
        }
        cursor
            .skip_form(spec.form)
            .expect("malformed DWARF attribute form");
    }
    (addr_base, str_offsets_base, rnglists_base)
}
