use super::constants::*;
use crate::error::{Error, Result};

/// A position-tracking reader over a byte section. Offsets returned by
/// `position` are relative to the start of `data`.
#[derive(Clone)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn at(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn is_finished(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn skip(&mut self, n: usize) {
        self.pos += n;
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        slice
    }

    pub fn u8(&mut self) -> u8 {
        let value = self.data[self.pos];
        self.pos += 1;
        value
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take(2).try_into().unwrap())
    }

    pub fn u24(&mut self) -> u32 {
        let lo = u32::from(self.u16());
        let hi = u32::from(self.u8());
        lo | (hi << 16)
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().unwrap())
    }

    pub fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().unwrap())
    }

    pub fn i8(&mut self) -> i8 {
        self.u8() as i8
    }

    pub fn i16(&mut self) -> i16 {
        self.u16() as i16
    }

    pub fn i32(&mut self) -> i32 {
        self.u32() as i32
    }

    pub fn i64(&mut self) -> i64 {
        self.u64() as i64
    }

    pub fn uleb128(&mut self) -> u64 {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let byte = self.u8();
            result |= u64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        result
    }

    pub fn sleb128(&mut self) -> i64 {
        let mut result = 0u64;
        let mut shift = 0;
        let mut byte;
        loop {
            byte = self.u8();
            result |= u64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        // Sign-extend: if the last byte's sign bit (0x40) is set, fill the remaining high bits
        // with ones. The shift < 64 guard avoids a shift-past-width overflow.
        if shift < 64 && byte & 0x40 != 0 {
            result |= u64::MAX << shift;
        }
        result as i64
    }

    /// Read a NUL-terminated UTF-8 string and advance past the terminator.
    pub fn cstr(&mut self) -> &'a str {
        let start = self.pos;
        while self.data[self.pos] != 0 {
            self.pos += 1;
        }
        let bytes = &self.data[start..self.pos];
        self.pos += 1;
        std::str::from_utf8(bytes).unwrap_or("")
    }

    /// Advance past one attribute value of the given form without decoding it.
    pub fn skip_form(&mut self, form: u64) -> Result<()> {
        match form {
            // No bytes in the DIE: the value lives in the abbreviation, not the data stream
            // (flag_present is implicitly 1, implicit_const is stored in the abbrev's spec).
            DW_FORM_flag_present | DW_FORM_implicit_const => {}

            // Host address size (8 bytes on x86-64).
            DW_FORM_addr => self.skip(8),

            // Offset into another section: 4 bytes in 32-bit DWARF.
            DW_FORM_ref_addr | DW_FORM_sec_offset | DW_FORM_strp | DW_FORM_strp_sup
            | DW_FORM_line_strp => self.skip(4),

            // 1-byte fixed size.
            DW_FORM_data1 | DW_FORM_flag | DW_FORM_ref1 | DW_FORM_addrx1 | DW_FORM_strx1 => {
                self.skip(1)
            }
            // 2-byte fixed size.
            DW_FORM_data2 | DW_FORM_ref2 | DW_FORM_addrx2 | DW_FORM_strx2 => self.skip(2),
            // 3-byte fixed size (DWARF 5 indexed forms).
            DW_FORM_addrx3 | DW_FORM_strx3 => self.skip(3),
            // 4-byte fixed size.
            DW_FORM_data4 | DW_FORM_ref4 | DW_FORM_addrx4 | DW_FORM_strx4 | DW_FORM_ref_sup4 => {
                self.skip(4)
            }
            // 8-byte fixed size.
            DW_FORM_data8 | DW_FORM_ref8 | DW_FORM_ref_sig8 | DW_FORM_ref_sup8 => self.skip(8),
            // 16-byte fixed size.
            DW_FORM_data16 => self.skip(16),

            // Variable-length signed LEB128.
            DW_FORM_sdata => {
                self.sleb128();
            }
            // Variable-length unsigned LEB128.
            DW_FORM_udata | DW_FORM_ref_udata | DW_FORM_strx | DW_FORM_addrx | DW_FORM_loclistx
            | DW_FORM_rnglistx => {
                self.uleb128();
            }

            // Blocks: a ULEB128 length prefix followed by that many bytes.
            DW_FORM_block | DW_FORM_exprloc => {
                let len = self.uleb128() as usize;
                self.skip(len);
            }
            // Blocks with a fixed-width length prefix.
            DW_FORM_block1 => {
                let len = self.u8() as usize;
                self.skip(len);
            }
            DW_FORM_block2 => {
                let len = self.u16() as usize;
                self.skip(len);
            }
            DW_FORM_block4 => {
                let len = self.u32() as usize;
                self.skip(len);
            }

            // Inline NUL-terminated string.
            DW_FORM_string => {
                self.cstr();
            }

            // The real form is itself encoded as a ULEB128 at the value's position.
            DW_FORM_indirect => {
                let form = self.uleb128();
                self.skip_form(form)?;
            }
            other => return Err(Error::new(format!("Unrecognized DWARF form: {other:#x}"))),
        }
        Ok(())
    }
}
