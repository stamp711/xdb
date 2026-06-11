use super::Dwarf;
use super::constants::*;
use super::cursor::Cursor;
use super::die::DieHandle;
use super::range_list::RangeList;
use super::unit::CuId;
use crate::error::{Error, Result};
use crate::types::FileAddr;

/// A single attribute of a DIE, resolved lazily from its form and the byte
/// offset of its value in `.debug_info`.
pub struct Attr<'dw> {
    pub(crate) dwarf: &'dw Dwarf,
    pub(crate) cu: CuId,
    pub(crate) attr: u64,
    pub(crate) form: u64,
    pub(crate) offset: usize,
    pub(crate) implicit_const: i64,
}

impl<'dw> Attr<'dw> {
    pub fn name(&self) -> u64 {
        self.attr
    }

    pub fn form(&self) -> u64 {
        self.form
    }

    fn cursor(&self) -> Cursor<'dw> {
        Cursor::at(self.dwarf.debug_info(), self.offset)
    }

    pub fn as_address(&self) -> Result<FileAddr> {
        let mut c = self.cursor();
        match self.form {
            DW_FORM_addr => Ok(FileAddr(c.u64())),
            DW_FORM_addrx => Ok(self.dwarf.resolve_addr_index(self.cu, c.uleb128())),
            DW_FORM_addrx1 => Ok(self.dwarf.resolve_addr_index(self.cu, u64::from(c.u8()))),
            DW_FORM_addrx2 => Ok(self.dwarf.resolve_addr_index(self.cu, u64::from(c.u16()))),
            DW_FORM_addrx3 => Ok(self.dwarf.resolve_addr_index(self.cu, u64::from(c.u24()))),
            DW_FORM_addrx4 => Ok(self.dwarf.resolve_addr_index(self.cu, u64::from(c.u32()))),
            form => Err(Error::new(format!("Invalid address form: {form:#x}"))),
        }
    }

    pub fn as_section_offset(&self) -> Result<u32> {
        if self.form != DW_FORM_sec_offset {
            return Err(Error::new(format!(
                "Invalid section offset form: {:#x}",
                self.form
            )));
        }
        Ok(self.cursor().u32())
    }

    pub fn as_int(&self) -> Result<u64> {
        if self.form == DW_FORM_implicit_const {
            return Ok(self.implicit_const as u64);
        }
        let mut c = self.cursor();
        match self.form {
            DW_FORM_data1 => Ok(u64::from(c.u8())),
            DW_FORM_data2 => Ok(u64::from(c.u16())),
            DW_FORM_data4 => Ok(u64::from(c.u32())),
            DW_FORM_data8 => Ok(c.u64()),
            DW_FORM_udata => Ok(c.uleb128()),
            form => Err(Error::new(format!("Invalid integer form: {form:#x}"))),
        }
    }

    pub fn as_block(&self) -> Result<&'dw [u8]> {
        let mut c = self.cursor();
        let len = match self.form {
            DW_FORM_block1 => usize::from(c.u8()),
            DW_FORM_block2 => usize::from(c.u16()),
            DW_FORM_block4 => c.u32() as usize,
            DW_FORM_block | DW_FORM_exprloc => c.uleb128() as usize,
            form => return Err(Error::new(format!("Invalid block form: {form:#x}"))),
        };
        let start = c.position();
        Ok(&self.dwarf.debug_info()[start..start + len])
    }

    pub fn as_string(&self) -> Result<&'dw str> {
        let mut c = self.cursor();
        match self.form {
            DW_FORM_string => Ok(c.cstr()),
            DW_FORM_strp => Ok(self.dwarf.str_at(".debug_str", c.u32() as usize)),
            DW_FORM_line_strp => Ok(self.dwarf.str_at(".debug_line_str", c.u32() as usize)),
            DW_FORM_strx => Ok(self.dwarf.resolve_str_index(self.cu, c.uleb128())),
            DW_FORM_strx1 => Ok(self.dwarf.resolve_str_index(self.cu, u64::from(c.u8()))),
            DW_FORM_strx2 => Ok(self.dwarf.resolve_str_index(self.cu, u64::from(c.u16()))),
            DW_FORM_strx3 => Ok(self.dwarf.resolve_str_index(self.cu, u64::from(c.u24()))),
            DW_FORM_strx4 => Ok(self.dwarf.resolve_str_index(self.cu, u64::from(c.u32()))),
            form => Err(Error::new(format!("Invalid string form: {form:#x}"))),
        }
    }

    pub fn as_reference(&self) -> Result<DieHandle> {
        let mut c = self.cursor();
        let cu_relative = match self.form {
            DW_FORM_ref1 => Some(u64::from(c.u8())),
            DW_FORM_ref2 => Some(u64::from(c.u16())),
            DW_FORM_ref4 => Some(u64::from(c.u32())),
            DW_FORM_ref8 => Some(c.u64()),
            DW_FORM_ref_udata => Some(c.uleb128()),
            _ => None,
        };
        if let Some(offset) = cu_relative {
            let cu_start = self.dwarf.unit(self.cu).range().start;
            return Ok(DieHandle {
                cu: self.cu,
                offset: cu_start + offset as usize,
            });
        }
        if self.form == DW_FORM_ref_addr {
            let offset = c.u32() as usize;
            let cu = self.dwarf.unit_containing_offset(offset)?;
            return Ok(DieHandle { cu, offset });
        }
        Err(Error::new(format!(
            "Invalid reference form: {:#x}",
            self.form
        )))
    }

    /// Resolve a `DW_AT_ranges` attribute to its range list in `.debug_rnglists`
    /// (DWARF 5 §7.28). `DW_FORM_sec_offset` is a byte offset, `DW_FORM_rnglistx` an index.
    pub fn as_range_list(&self) -> Result<RangeList<'dw>> {
        let section = self.dwarf.section(".debug_rnglists");
        let offset = match self.form {
            DW_FORM_sec_offset => self.as_section_offset()? as usize,
            DW_FORM_rnglistx => {
                // The index selects an entry in the offset table at DW_AT_rnglists_base;
                // each entry is a 4-byte offset (32-bit DWARF), relative to that same base.
                let index = self.cursor().uleb128() as usize;
                let base = self.dwarf.unit(self.cu).rnglists_base() as usize;
                let mut c = Cursor::at(section, base + index * 4);
                base + c.u32() as usize
            }
            form => return Err(Error::new(format!("Invalid range list form: {form:#x}"))),
        };

        // The default base address for offset-pair entries is the unit's low pc
        // (DWARF 5 §2.17.3), until a base-address entry overrides it.
        let base_address = self.dwarf.unit_base_address(self.cu)?;
        Ok(RangeList::new(self.dwarf, self.cu, offset, base_address))
    }
}
