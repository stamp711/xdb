use super::Dwarf;
use super::abbrev::Abbrev;
use super::attr::Attr;
use super::constants::*;
use super::cursor::Cursor;
use super::line_table::FileEntry;
use super::unit::CuId;
use crate::error::{Error, Result};
use crate::types::FileAddr;

/// A stable, copyable reference to a DIE by its position in `.debug_info`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DieHandle {
    pub cu: CuId,
    pub offset: usize,
}

/// A materialized view of a DIE: a handle plus the parsed abbreviation and the
/// byte offset of each of its attribute values. Created on demand; never stored.
pub struct DieRef<'dw> {
    dwarf: &'dw Dwarf,
    cu: CuId,
    offset: usize,
    abbrev: Option<&'dw Abbrev>,
    attr_offsets: Vec<usize>,
    next: usize,
}

pub(crate) fn parse_die(dwarf: &Dwarf, cu: CuId, offset: usize) -> DieRef<'_> {
    let info = dwarf.debug_info();
    let mut cursor = Cursor::at(info, offset);
    let code = cursor.uleb128();

    if code == 0 {
        return DieRef {
            dwarf,
            cu,
            offset,
            abbrev: None,
            attr_offsets: Vec::new(),
            next: cursor.position(),
        };
    }

    let abbrev = dwarf
        .unit(cu)
        .abbrev_table()
        .get(code)
        .expect("DIE references an unknown abbreviation code");
    let mut attr_offsets = Vec::with_capacity(abbrev.attrs.len());
    for spec in &abbrev.attrs {
        attr_offsets.push(cursor.position());
        cursor
            .skip_form(spec.form)
            .expect("malformed DWARF attribute form");
    }

    DieRef {
        dwarf,
        cu,
        offset,
        abbrev: Some(abbrev),
        attr_offsets,
        next: cursor.position(),
    }
}

impl<'dw> DieRef<'dw> {
    pub fn handle(&self) -> DieHandle {
        DieHandle {
            cu: self.cu,
            offset: self.offset,
        }
    }

    pub fn is_null(&self) -> bool {
        self.abbrev.is_none()
    }

    pub fn tag(&self) -> u64 {
        self.abbrev.map_or(0, |a| a.tag)
    }

    pub fn has_children(&self) -> bool {
        self.abbrev.is_some_and(|a| a.has_children)
    }

    pub fn contains(&self, attr: u64) -> bool {
        self.abbrev
            .is_some_and(|a| a.attrs.iter().any(|spec| spec.attr == attr))
    }

    pub fn attr(&self, attr: u64) -> Option<Attr<'dw>> {
        let abbrev = self.abbrev?;
        let index = abbrev.attrs.iter().position(|spec| spec.attr == attr)?;
        let spec = &abbrev.attrs[index];
        Some(Attr {
            dwarf: self.dwarf,
            cu: self.cu,
            attr: spec.attr,
            form: spec.form,
            offset: self.attr_offsets[index],
            implicit_const: spec.implicit_const,
        })
    }

    pub fn attrs(&self) -> impl Iterator<Item = Attr<'dw>> + '_ {
        let abbrev = self.abbrev;
        (0..self.attr_offsets.len()).map(move |i| {
            let spec = &abbrev.unwrap().attrs[i];
            Attr {
                dwarf: self.dwarf,
                cu: self.cu,
                attr: spec.attr,
                form: spec.form,
                offset: self.attr_offsets[i],
                implicit_const: spec.implicit_const,
            }
        })
    }

    pub fn children(&self) -> Children<'dw> {
        let current = self
            .has_children()
            .then(|| parse_die(self.dwarf, self.cu, self.next));
        Children {
            dwarf: self.dwarf,
            cu: self.cu,
            current,
        }
    }

    /// Most function DIEs carry their name in `DW_AT_name`. Two kinds encode it indirectly:
    /// an out-of-line definition (a member function declared in a header, defined in a `.cpp`)
    /// points to its declaration via `DW_AT_specification`;
    /// an inlined function points to its abstract origin via `DW_AT_abstract_origin`.
    /// Follow either reference to find the name.
    pub fn name(&self) -> Option<&'dw str> {
        if let Some(attr) = self.attr(DW_AT_name) {
            return attr.as_string().ok();
        }
        for indirect in [DW_AT_specification, DW_AT_abstract_origin] {
            if let Some(attr) = self.attr(indirect) {
                let handle = attr.as_reference().ok()?;
                return self.dwarf.die(handle).name();
            }
        }
        None
    }

    pub fn file(&self) -> Result<&'dw FileEntry> {
        let file_idx = if self.tag() == DW_TAG_inlined_subroutine {
            self.attr(DW_AT_call_file)
        } else {
            self.attr(DW_AT_decl_file)
        }
        .ok_or_else(|| Error::new("DIE has no file attribute"))?
        .as_int()?;
        // In DWARF 5, the 0th file is the primary file of this CU, it's now explicit.
        Ok(self
            .dwarf
            .line_table(self.cu)
            .ok_or_else(|| Error::new("CU has no line table"))?
            .file(file_idx))
    }

    pub fn line(&self) -> Result<u64> {
        if self.tag() == DW_TAG_inlined_subroutine {
            return self
                .attr(DW_AT_call_line)
                .ok_or_else(|| Error::new("DIE has no call line attribute"))?
                .as_int();
        }
        self.attr(DW_AT_decl_line)
            .ok_or_else(|| Error::new("DIE has no decl line attribute"))?
            .as_int()
    }

    pub fn low_pc(&self) -> Result<FileAddr> {
        if let Some(attr) = self.attr(DW_AT_ranges) {
            return attr
                .as_range_list()?
                .iter()
                .next()
                .map(|e| e.low)
                .ok_or_else(empty_ranges);
        }
        self.attr(DW_AT_low_pc)
            .expect("DIE has neither DW_AT_low_pc nor DW_AT_ranges")
            .as_address()
    }

    pub fn high_pc(&self) -> Result<FileAddr> {
        if let Some(attr) = self.attr(DW_AT_ranges) {
            return attr
                .as_range_list()?
                .iter()
                .last()
                .map(|e| e.high)
                .ok_or_else(empty_ranges);
        }
        let attr = self
            .attr(DW_AT_high_pc)
            .expect("DIE has neither DW_AT_high_pc nor DW_AT_ranges");
        // DWARF 5 §2.17.2: a class-address DW_AT_high_pc is the end address;
        // a class-constant one is an offset added to the low pc to get that end.
        if attr.form() == DW_FORM_addr {
            attr.as_address()
        } else {
            Ok(self.low_pc()? + attr.as_int()?)
        }
    }

    pub fn contains_address(&self, address: FileAddr) -> bool {
        if let Some(attr) = self.attr(DW_AT_ranges) {
            return attr
                .as_range_list()
                .is_ok_and(|list| list.contains(address));
        }
        if self.contains(DW_AT_low_pc) {
            return matches!((self.low_pc(), self.high_pc()), (Ok(low), Ok(high)) if low <= address && address < high);
        }
        false
    }
}

fn empty_ranges() -> crate::error::Error {
    crate::error::Error::new("DIE range list is empty")
}

/// Iterates the direct children of a DIE, skipping over each child's own
/// subtree to reach the next sibling.
pub struct Children<'dw> {
    dwarf: &'dw Dwarf,
    cu: CuId,
    current: Option<DieRef<'dw>>,
}

impl<'dw> Iterator for Children<'dw> {
    type Item = DieRef<'dw>;

    fn next(&mut self) -> Option<DieRef<'dw>> {
        let current = self.current.take()?;
        if current.is_null() {
            return None;
        }
        let sibling = sibling_offset(self.dwarf, self.cu, &current);
        self.current = Some(parse_die(self.dwarf, self.cu, sibling));
        Some(current)
    }
}

fn sibling_offset(dwarf: &Dwarf, cu: CuId, die: &DieRef<'_>) -> usize {
    if !die.has_children() {
        return die.next;
    }
    // Skip the subtree: descend on every DIE that has children, ascend on every
    // null terminator, until we return to this DIE's level.
    let mut depth = 1;
    let mut offset = die.next;
    loop {
        let entry = parse_die(dwarf, cu, offset);
        offset = entry.next;
        if entry.is_null() {
            depth -= 1;
            if depth == 0 {
                return offset;
            }
        } else if entry.has_children() {
            depth += 1;
        }
    }
}
