//! Call Frame Information: parsing `.eh_frame_hdr`/`.eh_frame` (CIE/FDE) and the `.eh_frame_hdr`
//! FDE lookup. Evaluating the CFI program into unwind rules is not implemented yet (book ch16).
//!
//! Notes: <https://publish.obsidian.md/stamp711/01+Atomic/Exception+Frames>

#![expect(dead_code)]

use std::ops::Range;

use super::Dwarf;
use super::constants::*;
use super::cursor::Cursor;
use crate::error::{Error, Result};
use crate::types::FileAddr;

/// Section base addresses (`sh_addr`, in file-address space) that pointer
/// encodings in the CFI are resolved against.
#[derive(Clone, Copy, Debug)]
pub struct BaseAddresses {
    pub eh_frame_hdr: u64,
    pub eh_frame: u64,
    pub text: u64,
}

/// Parsed metadata of the `.eh_frame_hdr` binary search table.
pub struct EhHdr {
    table_offset: usize,
    count: usize,
    table_encoding: u8,
}

struct Cie {
    code_alignment_factor: u64,
    data_alignment_factor: i64,
    return_address_register: u64,
    fde_has_augmentation: bool,
    fde_pointer_encoding: u8,
    instructions: Range<usize>,
}

struct Fde {
    cie: Cie,
    initial_location: FileAddr,
    address_range: u64,
    instructions: Range<usize>,
}

pub struct CallFrameInformation {
    eh_hdr: EhHdr,
    bases: BaseAddresses,
}

impl CallFrameInformation {
    pub(crate) fn parse(dwarf: &Dwarf, bases: BaseAddresses) -> Result<Option<Self>> {
        let section = dwarf.section(".eh_frame_hdr");
        if section.is_empty() {
            return Ok(None);
        }

        let mut cursor = Cursor::new(section);
        if cursor.u8() != 1 {
            return Err(Error::new("Unsupported .eh_frame_hdr version"));
        }
        let eh_frame_ptr_encoding = cursor.u8();
        let fde_count_encoding = cursor.u8();
        let table_encoding = cursor.u8();

        decode_pointer(
            &mut cursor,
            eh_frame_ptr_encoding,
            bases.eh_frame_hdr,
            &bases,
        )?;
        let count =
            decode_pointer(&mut cursor, fde_count_encoding, bases.eh_frame_hdr, &bases)? as usize;
        let table_offset = cursor.position();

        Ok(Some(Self {
            eh_hdr: EhHdr {
                table_offset,
                count,
                table_encoding,
            },
            bases,
        }))
    }

    /// Offset of the FDE covering `address`, by searching the `.eh_frame_hdr` binary search table.
    fn fde_offset(&self, dwarf: &Dwarf, address: FileAddr) -> Result<usize> {
        let section = dwarf.section(".eh_frame_hdr");
        let encoding_size = encoding_value_size(self.eh_hdr.table_encoding)?;
        let entry_size = encoding_size * 2; // Each entry consists of {initial_location, address}

        let initial_location = |index: usize| -> Result<u64> {
            let offset = self.eh_hdr.table_offset + index * entry_size;
            let mut cursor = Cursor::at(section, offset);
            decode_pointer(
                &mut cursor,
                self.eh_hdr.table_encoding,
                self.bases.eh_frame_hdr + offset as u64,
                &self.bases,
            )
        };

        // The table is sorted by initial location, so binary search for the
        // partition point and take the last entry at or below `address`.
        let mut low = 0;
        let mut high = self.eh_hdr.count;
        while low < high {
            let mid = low + (high - low) / 2;
            if initial_location(mid)? <= address.addr() {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        if low == 0 {
            return Err(Error::new("Address not covered by .eh_frame_hdr"));
        }
        let index = low - 1;

        let offset = self.eh_hdr.table_offset + index * entry_size + encoding_size;
        let mut cursor = Cursor::at(section, offset);
        let fde_address = decode_pointer(
            &mut cursor,
            self.eh_hdr.table_encoding,
            self.bases.eh_frame_hdr + offset as u64,
            &self.bases,
        )?;
        Ok((fde_address - self.bases.eh_frame) as usize)
    }
}

fn encoding_value_size(encoding: u8) -> Result<usize> {
    match u64::from(encoding & 0x0f) {
        DW_EH_PE_absptr | DW_EH_PE_udata8 | DW_EH_PE_sdata8 => Ok(8),
        DW_EH_PE_udata2 | DW_EH_PE_sdata2 => Ok(2),
        DW_EH_PE_udata4 | DW_EH_PE_sdata4 => Ok(4),
        other => Err(Error::new(format!(
            "Unsupported fixed-size pointer encoding: {other:#x}"
        ))),
    }
}

/// Decode a pointer at the cursor, applying the base implied by its encoding.
/// `position_address` is the runtime address of the encoded bytes themselves
/// (needed for pc-relative encodings).
///
/// See <https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html>.
fn decode_pointer(
    cursor: &mut Cursor<'_>,
    encoding: u8,
    position_address: u64,
    bases: &BaseAddresses,
) -> Result<u64> {
    let base = match u64::from(encoding & 0x70) {
        DW_EH_PE_absptr => 0,
        DW_EH_PE_pcrel => position_address,
        DW_EH_PE_textrel => bases.text,
        DW_EH_PE_datarel => bases.eh_frame_hdr,
        other => {
            return Err(Error::new(format!(
                "Unsupported pointer base encoding: {other:#x}"
            )));
        }
    };

    let value = match u64::from(encoding & 0x0f) {
        DW_EH_PE_absptr | DW_EH_PE_udata8 => cursor.u64(),
        DW_EH_PE_uleb128 => cursor.uleb128(),
        DW_EH_PE_udata2 => u64::from(cursor.u16()),
        DW_EH_PE_udata4 => u64::from(cursor.u32()),
        DW_EH_PE_sleb128 => cursor.sleb128() as u64,
        DW_EH_PE_sdata2 => i64::from(cursor.i16()) as u64,
        DW_EH_PE_sdata4 => i64::from(cursor.i32()) as u64,
        DW_EH_PE_sdata8 => cursor.i64() as u64,
        other => {
            return Err(Error::new(format!(
                "Unsupported pointer value encoding: {other:#x}"
            )));
        }
    };

    Ok(base.wrapping_add(value))
}

/// Parse CIE from cursor
fn parse_cie(eh_frame: &[u8], offset: usize) -> Result<Cie> {
    let mut cursor = Cursor::at(eh_frame, offset);

    let length = cursor.u32();
    if length == 0xffff_ffff {
        return Err(Error::new("64-bit CFI entries are not supported"));
    }
    let end = cursor.position() + length as usize;

    if cursor.u32() != 0 {
        return Err(Error::new("CIE id should be 0"));
    }
    let version = cursor.u8();
    if !matches!(version, 1 | 3 | 4) {
        return Err(Error::new("Unsupported CIE version"));
    }

    let augmentation = cursor.cstr().to_owned();
    if !augmentation.is_empty() && !augmentation.starts_with('z') {
        return Err(Error::new("Unsupported CIE augmentation"));
    }
    if version == 4 {
        let address_size = cursor.u8();
        let segment_size = cursor.u8();
        if address_size != 8 || segment_size != 0 {
            return Err(Error::new("Unsupported CIE address/segment size"));
        }
    }

    let code_alignment_factor = cursor.uleb128();
    let data_alignment_factor = cursor.sleb128();
    let return_address_register = if version == 1 {
        u64::from(cursor.u8())
    } else {
        cursor.uleb128()
    };

    // Default FDE pointer encoding when no 'R' augmentation is present.
    let mut fde_pointer_encoding = (DW_EH_PE_udata8 | DW_EH_PE_absptr) as u8;
    // See LSB 10.6.1.1.1 Augmentation String Format
    for byte in augmentation.bytes() {
        match byte {
            b'z' => {
                // augmentation data length
                cursor.uleb128();
            }
            b'R' => fde_pointer_encoding = cursor.u8(), // FDE pointer encoding
            b'L' => {
                // LSDA pointer encoding
                cursor.u8();
            }
            b'P' => {
                // eh_personality
                let encoding = cursor.u8();
                decode_pointer(
                    &mut cursor,
                    encoding,
                    0,
                    &BaseAddresses {
                        eh_frame_hdr: 0,
                        eh_frame: 0,
                        text: 0,
                    },
                )?;
            }
            other => {
                return Err(Error::new(format!(
                    "Unknown CIE augmentation: {}",
                    other as char
                )));
            }
        }
    }

    Ok(Cie {
        code_alignment_factor,
        data_alignment_factor,
        return_address_register,
        fde_has_augmentation: !augmentation.is_empty(),
        fde_pointer_encoding,
        instructions: cursor.position()..end,
    })
}

fn parse_fde(eh_frame: &[u8], offset: usize, bases: &BaseAddresses) -> Result<Fde> {
    let mut cursor = Cursor::at(eh_frame, offset);

    // Length
    let length = cursor.u32(); // does not include length field itself
    if length == 0xffff_ffff {
        return Err(Error::new("64-bit CFI entries are not supported"));
    }
    let end = cursor.position() + length as usize;

    // In `.eh_frame`, the CIE pointer is the distance backward from here.
    let cie_pointer_position = cursor.position();
    let cie_pointer = cursor.u32();
    let cie = parse_cie(eh_frame, cie_pointer_position - cie_pointer as usize)?;

    // Initial Location - encoding specified by CIE
    let position_address = bases.eh_frame + cursor.position() as u64;
    let initial_location = decode_pointer(
        &mut cursor,
        cie.fde_pointer_encoding,
        position_address,
        bases,
    )?;
    // The address range is a plain length, so decode without a base.
    let address_range = decode_pointer(&mut cursor, cie.fde_pointer_encoding & 0x0f, 0, bases)?;

    // Augmentation Data
    // Can only contain LSDA, ignore for now.
    if cie.fde_has_augmentation {
        let augmentation_length = cursor.uleb128() as usize;
        cursor.skip(augmentation_length);
    }

    Ok(Fde {
        cie,
        initial_location: FileAddr(initial_location),
        address_range,
        instructions: cursor.position()..end,
    })
}
