// DWARF constants keep their spec spellings (DW_FORM_addr, ...), which trips
// the style lint when they appear in match patterns.
#![allow(non_upper_case_globals)]

pub mod abbrev;
pub mod attr;
pub mod cfi;
pub mod constants;
pub mod cursor;
pub mod die;
pub mod line_table;
pub mod range_list;
pub mod unit;

use std::collections::HashMap;
use std::ops::Range;
use std::sync::{Arc, OnceLock};

use memmap2::Mmap;

use crate::elf::Elf;
use crate::error::{Error, Result};
use crate::types::FileAddr;
use cfi::{BaseAddresses, CallFrameInformation, UnwindTableRow};
use constants::*;
use die::{DieHandle, DieRef, parse_die};
use line_table::LineTable;
use unit::{CompileUnit, CuId, parse_units};

const SECTION_NAMES: &[&str] = &[
    ".debug_info",
    ".debug_abbrev",
    ".debug_str",
    ".debug_line_str",
    ".debug_str_offsets",
    ".debug_addr",
    ".debug_rnglists",
    ".debug_line",
    ".eh_frame",
    ".eh_frame_hdr",
];

/// Parsed DWARF data for one ELF. Owns a handle to the mapped file plus the
/// byte ranges of the debug sections, so it has no lifetime relationship with
/// the `Elf` it was created from.
pub struct Dwarf {
    data: Arc<Mmap>,
    sections: HashMap<&'static str, Range<usize>>,
    units: Vec<CompileUnit>,
    line_tables: Vec<Option<LineTable>>,
    cfi: Option<CallFrameInformation>,
    function_index: OnceLock<HashMap<String, Vec<DieHandle>>>,
}

impl Dwarf {
    pub fn new(elf: &Elf) -> Result<Self> {
        let mut sections = HashMap::new();
        for &name in SECTION_NAMES {
            if let Some(shdr) = elf.get_section_header(name) {
                let start = shdr.sh_offset as usize;
                sections.insert(name, start..start + shdr.sh_size as usize);
            }
        }

        let mut dwarf = Self {
            data: Arc::clone(elf.data()),
            sections,
            units: Vec::new(),
            line_tables: Vec::new(),
            cfi: None,
            function_index: OnceLock::new(),
        };
        dwarf.units = parse_units(dwarf.section(".debug_info"), dwarf.section(".debug_abbrev"))?;
        dwarf.line_tables = dwarf
            .units
            .iter()
            .map(|unit| line_table::parse_line_table(&dwarf, unit.id()))
            .collect::<Result<_>>()?;

        let section_addr = |name: &str| elf.get_section_header(name).map_or(0, |shdr| shdr.sh_addr);
        let bases = BaseAddresses {
            eh_frame_hdr: section_addr(".eh_frame_hdr"),
            eh_frame: section_addr(".eh_frame"),
            text: section_addr(".text"),
        };
        dwarf.cfi = CallFrameInformation::parse(&dwarf, bases)?;
        Ok(dwarf)
    }

    pub fn cfi(&self) -> Option<&CallFrameInformation> {
        self.cfi.as_ref()
    }

    #[expect(dead_code)]
    pub(crate) fn unwind_row(&self, pc: FileAddr) -> Result<UnwindTableRow> {
        self.cfi
            .as_ref()
            .ok_or_else(|| Error::new("Object has no call frame information"))?
            .unwind_row_for_addr(self, pc)
    }

    pub fn line_table(&self, id: CuId) -> Option<&LineTable> {
        self.line_tables[id.0].as_ref()
    }

    pub fn section(&self, name: &str) -> &[u8] {
        match self.sections.get(name) {
            Some(range) => &self.data[range.clone()],
            None => &[],
        }
    }

    pub fn debug_info(&self) -> &[u8] {
        self.section(".debug_info")
    }

    pub fn units(&self) -> &[CompileUnit] {
        &self.units
    }

    pub fn unit(&self, id: CuId) -> &CompileUnit {
        &self.units[id.0]
    }

    pub fn root(&self, id: CuId) -> DieRef<'_> {
        parse_die(self, id, self.unit(id).root_offset())
    }

    pub fn die(&self, handle: DieHandle) -> DieRef<'_> {
        parse_die(self, handle.cu, handle.offset)
    }

    pub(crate) fn unit_containing_offset(&self, offset: usize) -> Result<CuId> {
        self.units
            .iter()
            .find(|unit| unit.range().contains(&offset))
            .map(CompileUnit::id)
            .ok_or_else(|| {
                Error::new(format!(
                    "No compile unit contains .debug_info offset {offset:#x}"
                ))
            })
    }

    /// The default base address for the unit's range lists: the root DIE's
    /// `DW_AT_low_pc`, if present.
    pub(crate) fn unit_base_address(&self, id: CuId) -> Result<FileAddr> {
        let root = self.root(id);
        match root.attr(DW_AT_low_pc) {
            Some(attr) => attr.as_address(),
            None => Ok(FileAddr(0)),
        }
    }

    /// Read an address out of `.debug_addr` via the unit's `DW_AT_addr_base`.
    pub(crate) fn resolve_addr_index(&self, id: CuId, index: u64) -> FileAddr {
        let base = self.unit(id).addr_base() as usize;
        let mut cursor = cursor::Cursor::at(self.section(".debug_addr"), base + index as usize * 8);
        FileAddr(cursor.u64())
    }

    /// Read a string out of `.debug_str` via the unit's `DW_AT_str_offsets_base`.
    pub(crate) fn resolve_str_index(&self, id: CuId, index: u64) -> &str {
        let base = self.unit(id).str_offsets_base() as usize;
        let mut cursor = cursor::Cursor::at(
            self.section(".debug_str_offsets"),
            base + index as usize * 4,
        );
        let offset = cursor.u32() as usize;
        self.str_at(".debug_str", offset)
    }

    pub(crate) fn str_at(&self, section: &str, offset: usize) -> &str {
        cursor::Cursor::at(self.section(section), offset).cstr()
    }

    pub fn unit_containing_address(&self, address: FileAddr) -> Option<CuId> {
        self.units
            .iter()
            .map(CompileUnit::id)
            .find(|&id| self.root(id).contains_address(address))
    }

    pub fn function_containing_address(&self, address: FileAddr) -> Option<DieHandle> {
        self.function_index()
            .values()
            .flatten()
            .copied()
            .find(|&handle| {
                let die = self.die(handle);
                die.tag() == DW_TAG_subprogram && die.contains_address(address)
            })
    }

    pub fn find_functions(&self, name: &str) -> Vec<DieHandle> {
        self.function_index().get(name).cloned().unwrap_or_default()
    }

    /// The chain of functions whose code contains `address`: the outermost
    /// (non-inlined) function first, then each inlined subroutine in turn.
    pub fn inline_stack_at_address(&self, address: FileAddr) -> Vec<DieHandle> {
        let Some(function) = self.function_containing_address(address) else {
            return Vec::new();
        };

        let mut stack = vec![function];
        loop {
            let current = self.die(*stack.last().unwrap());
            let inlined = current.children().find(|child| {
                child.tag() == DW_TAG_inlined_subroutine && child.contains_address(address)
            });
            match inlined {
                Some(child) => stack.push(child.handle()),
                None => break,
            }
        }
        stack
    }

    fn function_index(&self) -> &HashMap<String, Vec<DieHandle>> {
        self.function_index.get_or_init(|| {
            let mut index = HashMap::new();
            for unit in &self.units {
                self.index_die(&self.root(unit.id()), &mut index);
            }
            index
        })
    }

    fn index_die(&self, die: &DieRef<'_>, index: &mut HashMap<String, Vec<DieHandle>>) {
        let is_function = die.tag() == DW_TAG_subprogram || die.tag() == DW_TAG_inlined_subroutine;
        // Skip declaration-only DIEs, which carry no code range.
        let has_range = die.contains(DW_AT_ranges)
            || (die.contains(DW_AT_low_pc) && die.contains(DW_AT_high_pc));
        if is_function
            && has_range
            && let Some(name) = die.name()
        {
            index.entry(name.to_owned()).or_default().push(die.handle());
        }

        for child in die.children() {
            self.index_die(&child, index);
        }
    }
}
