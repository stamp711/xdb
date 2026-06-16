//! Call Frame Information: parsing `.eh_frame_hdr`/`.eh_frame` (CIE/FDE) and the `.eh_frame_hdr`
//! FDE lookup. Evaluating the CFI program into unwind rules is not implemented yet (book ch16).
//!
//! Notes: <https://publish.obsidian.md/stamp711/01+Atomic/Exception+Frames>

#![expect(dead_code)]

use std::collections::HashMap;
use std::ops::Range;

use super::Dwarf;
use super::constants::*;
use super::cursor::Cursor;
use crate::error::{Error, Result};
use crate::types::FileAddr;

pub struct CallFrameInformation {
    eh_hdr: EhHdr,
    bases: BaseAddresses,
}

/// Parsed metadata of the `.eh_frame_hdr` binary search table.
pub struct EhHdr {
    table_offset: usize,
    count: usize,
    table_encoding: u8,
}

/// Section base addresses (`sh_addr`, in file-address space) that pointer
/// encodings in the CFI are resolved against.
#[derive(Clone, Copy, Debug)]
pub struct BaseAddresses {
    pub eh_frame_hdr: u64,
    pub eh_frame: u64,
    pub text: u64,
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
    fn fde_offset_for_addr(&self, dwarf: &Dwarf, address: FileAddr) -> Result<usize> {
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

    fn fde_for_addr(&self, dwarf: &Dwarf, address: FileAddr) -> Result<Fde> {
        let offset = self.fde_offset_for_addr(dwarf, address)?;
        parse_fde(dwarf.section(".eh_frame"), offset, &self.bases)
    }
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

/// How to unwind the canonical frame address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CfaRule {
    /// The CFA is calculated by register R's value + offset N
    RegisterAndOffset { register: u64, offset: i64 },
    // /// The CFA is calculated by executing the DWARF expression E
    // Expression(E),
}

/// How to recover one register's caller value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RegisterRule {
    /// Not possible to restore
    Undefined,
    /// Stored in another register
    Register(u64),
    /// Same register
    SameValue,
    /// Stored in offset N from current CFA
    Offset(i64),
    /// Value is CFA + N
    ValOffset(i64),
    // /// Located at the address produced by executing DWARF expression E
    // Expression(E),
    // /// Value is produced by executing DWARF expression E.
    // ValExpression(E),
}

pub(crate) type RegisterRules = HashMap<u64, RegisterRule>;

struct UnwindContext {
    location: u64,
    bases: BaseAddresses,
    cfa_rule: Option<CfaRule>,
    register_rules: RegisterRules,
    cie_register_rules: RegisterRules,
    stack: Vec<(Option<CfaRule>, RegisterRules)>,
}

impl UnwindContext {
    fn new(initial_location: u64, bases: BaseAddresses) -> Self {
        Self {
            location: initial_location,
            bases,
            cfa_rule: None,
            register_rules: HashMap::new(),
            cie_register_rules: HashMap::new(),
            stack: Vec::new(),
        }
    }

    fn run_cie(&mut self, eh_frame: &[u8], cie: &Cie) -> Result<()> {
        self.run(eh_frame, cie.instructions.clone(), None, cie)?;
        self.cie_register_rules = self.register_rules.clone();
        Ok(())
    }

    fn run_fde(&mut self, eh_frame: &[u8], fde: &Fde, target: Option<u64>) -> Result<()> {
        if self.location != fde.initial_location.addr() {
            panic!("FDE initial location does not match current location");
        }
        self.run(eh_frame, fde.instructions.clone(), target, &fde.cie)?;
        Ok(())
    }

    /// Move to a new (always-greater) absolute location. Returns true if `target`
    /// is reached, per DWARF5.pdf P.181 6.4.3 terminal logic.
    fn advance_location(&mut self, loc: u64, target: Option<u64>) -> Result<bool> {
        if loc < self.location {
            return Err(Error::new(format!(
                "CFI location moved backwards: {loc:#x} < {:#x}",
                self.location
            )));
        }
        self.location = loc;
        Ok(matches!(target, Some(t) if loc > t))
    }

    /// Run the instructions, modifying the unwind context.
    /// If `target` is Some, only run up to the point where next instruction would make `location` > `target`.
    fn run(
        &mut self,
        eh_frame: &[u8],
        instructions: Range<usize>,
        target: Option<u64>,
        cie: &Cie,
    ) -> Result<()> {
        let mut cursor = Cursor::at(eh_frame, instructions.start);

        while cursor.position() < instructions.end {
            // Ref: DWARF5.pdf, P.239
            // CFIs are encoded in one or more bytes, grab the first one.
            let op = cursor.u8();
            let _hi2 = op & 0xc0;
            let lo6 = op & 0x3f;

            // hi2 + lo6 opcodes
            match op as u64 {
                // ========== 6.4.2.1 Row Creation Instructions ==========

                // Create a new table row using the specified address as the location.
                // The new location is always greater than the current one.
                DW_CFA_set_loc => {
                    let position_address = self.bases.eh_frame + cursor.position() as u64;
                    // Note: we only support segment_size == 0, so no segment selector here.
                    let loc = decode_pointer(
                        &mut cursor,
                        cie.fde_pointer_encoding,
                        position_address,
                        &self.bases,
                    )?;
                    if self.advance_location(loc, target)? {
                        break;
                    }
                }

                // hi2 = 0x1
                DW_CFA_advance_loc..DW_CFA_offset => {
                    let delta = lo6 as u64;
                    let inc = delta * cie.code_alignment_factor;
                    if self.advance_location(self.location + inc, target)? {
                        break;
                    }
                }

                DW_CFA_advance_loc1 | DW_CFA_advance_loc2 | DW_CFA_advance_loc4 => {
                    let inc = match op as u64 {
                        DW_CFA_advance_loc1 => u64::from(cursor.u8()),
                        DW_CFA_advance_loc2 => u64::from(cursor.u16()),
                        DW_CFA_advance_loc4 => cursor.u32() as u64,
                        _ => unreachable!(),
                    } * cie.code_alignment_factor;
                    if self.advance_location(self.location + inc, target)? {
                        break;
                    }
                }

                // ========== 6.4.2.2 CFA Definition Instructions ==========
                DW_CFA_def_cfa => {
                    self.cfa_rule = Some(CfaRule::RegisterAndOffset {
                        register: cursor.uleb128(),
                        offset: cursor.uleb128() as i64, // (unsigned non-factored)
                    });
                }

                DW_CFA_def_cfa_sf => {
                    self.cfa_rule = Some(CfaRule::RegisterAndOffset {
                        register: cursor.uleb128(),
                        offset: cursor.sleb128() * cie.data_alignment_factor,
                    });
                }

                DW_CFA_def_cfa_register => match &mut self.cfa_rule {
                    Some(CfaRule::RegisterAndOffset { register: reg, .. }) => {
                        *reg = cursor.uleb128();
                    }
                    _ => {
                        // DWARF5.pdf, P.178
                        return Err(Error::new(
                            "def_cfa_register requires current CFA rule to be RegisterAndOffset",
                        ));
                    }
                },

                DW_CFA_def_cfa_offset => match &mut self.cfa_rule {
                    Some(CfaRule::RegisterAndOffset { offset, .. }) => {
                        *offset = cursor.uleb128() as i64; // (unsigned non-factored)
                    }
                    _ => {
                        return Err(Error::new(
                            "def_cfa_offset requires current CFA rule to be RegisterAndOffset",
                        ));
                    }
                },

                DW_CFA_def_cfa_offset_sf => match &mut self.cfa_rule {
                    Some(CfaRule::RegisterAndOffset { offset, .. }) => {
                        *offset = cursor.sleb128() * cie.data_alignment_factor;
                    }
                    _ => {
                        return Err(Error::new(
                            "def_cfa_offset_sf requires current CFA rule to be RegisterAndOffset",
                        ));
                    }
                },

                DW_CFA_def_cfa_expression => unimplemented!(),

                // ========== 6.4.2.3 Register Rule Instructions ==========
                DW_CFA_undefined => {
                    self.register_rules
                        .insert(cursor.uleb128(), RegisterRule::Undefined);
                }

                DW_CFA_same_value => {
                    self.register_rules
                        .insert(cursor.uleb128(), RegisterRule::SameValue);
                }

                // hi2 = 0x2
                // Set register rule to Offset(N)
                DW_CFA_offset..DW_CFA_restore => {
                    self.register_rules.insert(
                        lo6 as u64,
                        RegisterRule::Offset(cursor.uleb128() as i64 * cie.data_alignment_factor),
                    );
                }

                DW_CFA_offset_extended => {
                    self.register_rules.insert(
                        cursor.uleb128(),
                        RegisterRule::Offset(cursor.uleb128() as i64 * cie.data_alignment_factor),
                    );
                }

                DW_CFA_offset_extended_sf => {
                    self.register_rules.insert(
                        cursor.uleb128(),
                        RegisterRule::Offset(cursor.sleb128() * cie.data_alignment_factor),
                    );
                }

                DW_CFA_val_offset => {
                    self.register_rules.insert(
                        cursor.uleb128(),
                        RegisterRule::ValOffset(
                            cursor.uleb128() as i64 * cie.data_alignment_factor,
                        ),
                    );
                }

                DW_CFA_val_offset_sf => {
                    self.register_rules.insert(
                        cursor.uleb128(),
                        RegisterRule::ValOffset(cursor.sleb128() * cie.data_alignment_factor),
                    );
                }

                DW_CFA_register => {
                    self.register_rules
                        .insert(cursor.uleb128(), RegisterRule::Register(cursor.uleb128()));
                }

                DW_CFA_expression => unimplemented!(),

                DW_CFA_val_expression => unimplemented!(),

                // hi2 = 0x3
                // Restore register rule to from CIE
                DW_CFA_restore.. => {
                    let register = lo6 as u64;
                    match self.cie_register_rules.get(&register) {
                        None => self.register_rules.remove(&register),
                        Some(rule) => self.register_rules.insert(register, *rule),
                    };
                }

                DW_CFA_restore_extended => {
                    let register = cursor.uleb128();
                    match self.cie_register_rules.get(&register) {
                        None => self.register_rules.remove(&register),
                        Some(rule) => self.register_rules.insert(register, *rule),
                    };
                }

                // ========== 6.4.2.4 Row State Instructions ==========
                DW_CFA_remember_state => {
                    self.stack
                        .push((self.cfa_rule, self.register_rules.clone()));
                }

                DW_CFA_restore_state => {
                    (self.cfa_rule, self.register_rules) = self
                        .stack
                        .pop()
                        .ok_or_else(|| Error::new("CFA stack underflow at restore_state"))?;
                }

                // ========== 6.4.2.5 Padding Instruction ==========
                DW_CFA_nop => {}

                DW_CFA_low_user..=DW_CFA_high_user => {
                    return Err(Error::new(format!(
                        "Encountered vendor specific CFI opcode: {op:#x}"
                    )));
                }

                other => return Err(Error::new(format!("Unsupported CFI opcode: {other:#x}"))),
            };
        }

        Ok(())
    }
}

pub(crate) struct UnwindRow {
    pub(crate) cfa_rule: CfaRule,
    pub(crate) register_rules: RegisterRules,
}

impl CallFrameInformation {
    pub(crate) fn unwind_row_for_addr(&self, dwarf: &Dwarf, pc: FileAddr) -> Result<UnwindRow> {
        let fde = self.fde_for_addr(dwarf, pc)?;

        if pc < fde.initial_location
            || pc >= FileAddr(fde.initial_location.addr() + fde.address_range)
        {
            return Err(Error::new("No unwind information at PC"));
        }

        let eh_frame = dwarf.section(".eh_frame");

        let mut ctx = UnwindContext::new(fde.initial_location.addr(), self.bases);
        ctx.run_cie(eh_frame, &fde.cie)?;
        ctx.run_fde(eh_frame, &fde, Some(pc.addr()))?;

        Ok(UnwindRow {
            cfa_rule: ctx
                .cfa_rule
                .ok_or_else(|| Error::new("CFA rule not defined at PC"))?,
            register_rules: ctx.register_rules,
        })
    }
}
