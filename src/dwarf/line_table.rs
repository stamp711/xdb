use std::ops::Range;
use std::path::{Path, PathBuf};

use super::Dwarf;
use super::constants::*;
use super::cursor::Cursor;
use super::unit::CuId;
use crate::error::{Error, Result};
use crate::types::FileAddr;

#[derive(Clone, Debug)]
pub struct FileEntry {
    pub path: PathBuf,
    pub directory_index: u64,
}

#[derive(Clone, Debug)]
pub struct SourceLocation {
    pub file: FileEntry,
    pub line: u64,
}

/// The decoded header of one compilation unit's line number program. Rows are
/// produced on demand by running the program (`rows`).
pub struct LineTable {
    program: Range<usize>,
    default_is_stmt: bool, // The initial value of the is_stmt register.
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
    files: Vec<FileEntry>,
}

/// One row of the line table: the source position for an address.
#[derive(Clone, Debug)]
pub struct LineEntry {
    pub address: FileAddr,
    pub file_index: u64,
    pub line: u64,
    pub column: u64,
    pub is_stmt: bool,
    pub basic_block: bool,
    pub end_sequence: bool,
    pub prologue_end: bool,
    pub epilogue_begin: bool,
    pub discriminator: u64,
}

impl LineEntry {
    // §6.2.2: Line number program initial state
    fn initial(default_is_stmt: bool) -> Self {
        Self {
            address: FileAddr(0),
            file_index: 1,
            line: 1,
            column: 0,
            is_stmt: default_is_stmt,
            basic_block: false,
            end_sequence: false,
            prologue_end: false,
            epilogue_begin: false,
            discriminator: 0,
        }
    }
}

/// Two rows are the same source position if they agree on address, file, line,
/// column, and discriminator; the boolean flags don't affect identity.
impl PartialEq for LineEntry {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
            && self.file_index == other.file_index
            && self.line == other.line
            && self.column == other.column
            && self.discriminator == other.discriminator
    }
}

impl LineTable {
    pub fn files(&self) -> &[FileEntry] {
        &self.files
    }

    pub fn file(&self, index: u64) -> &FileEntry {
        &self.files[index as usize]
    }

    pub fn rows<'dw>(&'dw self, dwarf: &'dw Dwarf) -> LineRows<'dw> {
        LineRows {
            table: self,
            cursor: Cursor::at(dwarf.section(".debug_line"), self.program.start),
            end: self.program.end,
            registers: LineEntry::initial(self.default_is_stmt),
        }
    }

    /// The row covering `address`: the last non-end-sequence row at or below it
    /// whose successor lies above it.
    pub fn entry_at_address(&self, dwarf: &Dwarf, address: FileAddr) -> Option<LineEntry> {
        let mut rows = self.rows(dwarf);
        let mut previous = rows.next()?;
        for row in rows {
            if previous.address <= address && address < row.address && !previous.end_sequence {
                return Some(previous);
            }
            previous = row;
        }
        None
    }

    /// The row immediately after the one covering `address`.
    pub fn entry_following_address(&self, dwarf: &Dwarf, address: FileAddr) -> Option<LineEntry> {
        let entry = self.entry_at_address(dwarf, address)?;
        self.entry_after(dwarf, &entry)
    }

    pub fn entries_by_line(&self, dwarf: &Dwarf, path: &Path, line: u64) -> Vec<LineEntry> {
        self.rows(dwarf)
            .filter(|row| {
                row.line == line && {
                    let file = &self.file(row.file_index).path;
                    if path.is_absolute() {
                        file == path
                    } else {
                        path_ends_in(file, path)
                    }
                }
            })
            .collect()
    }

    /// The row immediately following `entry` in program order.
    pub fn entry_after(&self, dwarf: &Dwarf, entry: &LineEntry) -> Option<LineEntry> {
        let mut rows = self.rows(dwarf).skip_while(|row| row != entry);
        rows.next();
        rows.next()
    }
}

pub fn path_ends_in(path: &Path, suffix: &Path) -> bool {
    let path: Vec<_> = path.components().collect();
    let suffix: Vec<_> = suffix.components().collect();
    path.len() >= suffix.len() && path[path.len() - suffix.len()..] == suffix[..]
}

/// Executes the line number program, yielding one `LineEntry` per emitted row.
pub struct LineRows<'dw> {
    table: &'dw LineTable,
    cursor: Cursor<'dw>,
    end: usize,
    registers: LineEntry,
}

impl Iterator for LineRows<'_> {
    type Item = LineEntry;

    fn next(&mut self) -> Option<LineEntry> {
        while self.cursor.position() < self.end {
            if let Some(row) = self.execute_instruction() {
                return Some(row);
            }
        }
        None
    }
}

impl LineRows<'_> {
    fn emit(&mut self) -> LineEntry {
        let row = self.registers.clone();
        if self.registers.end_sequence {
            self.registers = LineEntry::initial(self.table.default_is_stmt);
        } else {
            self.registers.basic_block = false;
            self.registers.prologue_end = false;
            self.registers.epilogue_begin = false;
            self.registers.discriminator = 0;
        }
        row
    }

    fn execute_instruction(&mut self) -> Option<LineEntry> {
        let table = self.table;
        let opcode = self.cursor.u8();

        // §6.2.5: Line Number Program Instructions
        if opcode >= table.opcode_base {
            // §6.2.5.1 special opcodes
            //
            // Most of the instructions in a line number program are special opcodes.
            // Their purpose is to efficiently encode address and line changes.
            // See Appendix D.5 for an example special opcode encoding table.
            let adjusted = opcode - table.opcode_base;
            self.registers.address =
                self.registers.address + u64::from(adjusted / table.line_range);
            let line_delta = i64::from(table.line_base) + i64::from(adjusted % table.line_range);
            self.registers.line = self
                .registers
                .line
                .checked_add_signed(line_delta)
                .expect("line went negative");
            return Some(self.emit());
        }

        // §6.2.5.2: standard opcodes
        if opcode > 0 {
            match u64::from(opcode) {
                // The DW_LNS_copy opcode takes no operands. It appends a row to the matrix using
                // the current values of the state machine registers. Then it sets the
                // discriminator register to 0, and sets the basic_block, prologue_end and
                // epilogue_begin registers to "false."
                DW_LNS_copy => return Some(self.emit()),
                // The DW_LNS_advance_pc opcode takes a single unsigned LEB128 operand as the
                // operation advance and modifies the address and op_index registers as specified
                // in Section 6.2.5.1.
                //
                // We only support minimum_instruction_length and
                // maximum_operations_per_instruction = 1
                DW_LNS_advance_pc => {
                    let advance = self.cursor.uleb128();
                    self.registers.address = self.registers.address + advance;
                }
                // The DW_LNS_advance_line opcode takes a single signed LEB128 operand and adds
                // that value to the line register of the state machine.
                DW_LNS_advance_line => {
                    let delta = self.cursor.sleb128();
                    self.registers.line = self
                        .registers
                        .line
                        .checked_add_signed(delta)
                        .expect("line went negative");
                }
                DW_LNS_set_file => self.registers.file_index = self.cursor.uleb128(),
                DW_LNS_set_column => self.registers.column = self.cursor.uleb128(),
                // The DW_LNS_negate_stmt opcode takes no operands. It sets the is_stmt register of
                // the state machine to the logical negation of its current value.
                DW_LNS_negate_stmt => self.registers.is_stmt = !self.registers.is_stmt,
                // The DW_LNS_set_basic_block opcode takes no operands. It sets the basic_block
                // register of the state machine to "true."
                DW_LNS_set_basic_block => self.registers.basic_block = true,
                // The DW_LNS_const_add_pc opcode takes no operands. It advances the address and
                // op_index registers by the increments corresponding to special opcode 255.
                //
                // When the line number program needs to advance the address by a small amount, it
                // can use a single special opcode, which occupies a single byte. When it needs to
                // advance the address by up to twice the range of the last special opcode, it can
                // use DW_LNS_const_add_pc followed by a special opcode, for a total of two bytes.
                // Only if it needs to advance the address by more than twice that range will it
                // need to use both DW_LNS_advance_pc and a special opcode, requiring three or more
                // bytes.
                DW_LNS_const_add_pc => {
                    let advance = u64::from((255 - table.opcode_base) / table.line_range);
                    self.registers.address = self.registers.address + advance;
                }
                // The DW_LNS_fixed_advance_pc opcode takes a single uhalf (unencoded) operand and
                // adds it to the address register of the state machine and sets the op_index
                // register to 0. This is the only standard opcode whose operand is not a variable
                // length number. It also does not multiply the operand by the
                // minimum_instruction_length field of the header.
                //
                // Some assemblers may not be able emit DW_LNS_advance_pc or special opcodes
                // because they cannot encode LEB128 numbers or judge when the computation of a
                // special opcode overflows and requires the use of DW_LNS_advance_pc. Such
                // assemblers, however, can use DW_LNS_fixed_advance_pc instead, sacrificing
                // compression.
                DW_LNS_fixed_advance_pc => {
                    let advance = u64::from(self.cursor.u16());
                    self.registers.address = self.registers.address + advance;
                }
                // The DW_LNS_set_prologue_end opcode takes no operands. It sets the prologue_end
                // register to "true."
                DW_LNS_set_prologue_end => self.registers.prologue_end = true,
                DW_LNS_set_epilogue_begin => self.registers.epilogue_begin = true,
                // The DW_LNS_set_isa opcode takes a single unsigned LEB128 operand and stores that
                // value in the isa register of the state machine.
                //
                // We ignore the isa because we only support x86_64
                DW_LNS_set_isa => {
                    self.cursor.uleb128();
                }
                other => panic!("unexpected standard opcode: {other}"),
            }
            return None;
        }

        // §6.2.5.3: extended opcodes
        let _length = self.cursor.uleb128();
        let extended = u64::from(self.cursor.u8());
        match extended {
            DW_LNE_end_sequence => {
                self.registers.end_sequence = true;
                return Some(self.emit());
            }
            DW_LNE_set_address => self.registers.address = FileAddr(self.cursor.u64()),
            DW_LNE_set_discriminator => self.registers.discriminator = self.cursor.uleb128(),
            other => panic!("unexpected or unsupported extended opcode: {other}"),
        }
        None
    }
}

pub(crate) fn parse_line_table(dwarf: &Dwarf, cu: CuId) -> Result<Option<LineTable>> {
    let Some(stmt_list) = dwarf.root(cu).attr(DW_AT_stmt_list) else {
        return Ok(None);
    };
    let offset = stmt_list.as_section_offset()? as usize;
    let section = dwarf.section(".debug_line");
    let mut cursor = Cursor::at(section, offset);

    // §6.2.4: Line Number Program header format
    let unit_length = cursor.u32();
    if unit_length >= 0xfff_ffff0 {
        return Err(Error::new(
            "Initial length extension values are not supported",
        ));
    }
    let end = cursor.position() + unit_length as usize;

    let version = cursor.u16();
    if version != 5 {
        return Err(Error::new("Only line table version 5 is supported"));
    }
    let address_size = cursor.u8();
    if address_size != 8 {
        return Err(Error::new("Unsupported line table address size"));
    }
    let segment_selector_size = cursor.u8();
    if segment_selector_size != 0 {
        return Err(Error::new("Unsupported segment selector size"));
    }
    let _header_length = cursor.u32();

    let minimum_instruction_length = cursor.u8();
    if minimum_instruction_length != 1 {
        return Err(Error::new("Unexpected minimum_instruction_length"));
    }
    let maximum_operations_per_instruction = cursor.u8();
    if maximum_operations_per_instruction != 1 {
        return Err(Error::new("Unexpected maximum_operations_per_instruction"));
    }

    let default_is_stmt = cursor.u8() != 0;
    let line_base = cursor.i8();
    let line_range = cursor.u8();
    let opcode_base = cursor.u8();

    // §6.2.5.2: Standard Opcodes
    let expected_lengths: [u8; 12] = [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1];
    if opcode_base as usize - 1 > expected_lengths.len() {
        return Err(Error::new("Unexpected opcode_base"));
    }
    // It may only use a subset of standard opcodes
    for expected in expected_lengths.iter().take(opcode_base as usize - 1) {
        if cursor.u8() != *expected {
            return Err(Error::new("Unexpected standard opcode length"));
        }
    }

    // directories
    //
    // A sequence of directory names and optional related information. Each entry is encoded as
    // described by the directory_entry_format field.
    //
    // The first entry is the current directory of the compilation. Each additional path entry is
    // either a full path name or is relative to the current directory of the compilation.
    //
    // The line number program assigns a number (index) to each of the directory entries in order,
    // beginning with 0.
    //
    // Prior to DWARF Version 5, the current directory was not represented in the directories field
    // and a directory index of 0 implicitly referred to that directory as found in the
    // DW_AT_comp_dir attribute of the compilation unit debugging information entry. In DWARF
    // Version 5, the current directory is explicitly present in the directories field. This is
    // needed to support the common practice of stripping all but the line number sections
    // (.debug_line and .debug_line_str) from an executable.
    let directories = parse_entries(dwarf, cu, &mut cursor)?
        .into_iter()
        .map(|(path, _)| path)
        .collect::<Vec<_>>();

    // file_names
    //
    // A sequence of file names and optional related information. Each entry is encoded as
    // described by the file_name_entry_format field.
    //
    // Entries in this sequence describe source files that contribute to the line number
    // information for this compilation or is used in other contexts, such as in a declaration
    // coordinate or a macro file inclusion.
    //
    // The first entry in the sequence is the primary source file whose file name exactly matches
    // that given in the DW_AT_name attribute in the compilation unit debugging information entry.
    //
    // The line number program references file names in this sequence beginning with 0, and uses
    // those numbers instead of file names in the line number program that follows.
    //
    // Prior to DWARF Version 5, the current compilation file name was not represented in the
    // file_names field. In DWARF Version 5, the current compilation file name is explicitly
    // present and has index 0. This is needed to support the common practice of stripping all but
    // the line number sections (.debug_line and .debug_line_str) from an executable.
    let files = parse_entries(dwarf, cu, &mut cursor)?
        .into_iter()
        .map(|(path, directory_index)| {
            let path = if path.is_relative() {
                directories[directory_index as usize].join(path)
            } else {
                path
            };
            FileEntry {
                path,
                directory_index,
            }
        })
        .collect();

    Ok(Some(LineTable {
        program: cursor.position()..end,
        default_is_stmt,
        line_base,
        line_range,
        opcode_base,
        files,
    }))
}

/// Parse a v5 directory or file-name entry list: a format description followed
/// by entries, from which only the path and directory index are kept.
fn parse_entries(dwarf: &Dwarf, cu: CuId, cursor: &mut Cursor<'_>) -> Result<Vec<(PathBuf, u64)>> {
    // A sequence of entry format descriptions (directory_entry_format / file_name_entry_format).
    // Each description consists of a pair of ULEB128 values:
    // - A content type code (see Sections 6.2.4.1 and 6.2.4.2).
    // - A form code using the attribute form codes
    let format_count = cursor.u8();
    let mut formats = Vec::with_capacity(format_count as usize);
    for _ in 0..format_count {
        let content_type = cursor.uleb128();
        let form = cursor.uleb128();
        formats.push((content_type, form));
    }

    let count = cursor.uleb128();
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut path = PathBuf::new();
        let mut directory_index = 0;
        for &(content_type, form) in &formats {
            // §6.2.4.1: Standard & Vendor-defined Content Descriptions
            match content_type {
                DW_LNCT_path => path = PathBuf::from(read_form_string(dwarf, cu, cursor, form)?),
                DW_LNCT_directory_index => directory_index = read_form_int(cursor, form)?,
                _ => cursor.skip_form(form)?,
            }
        }
        entries.push((path, directory_index));
    }
    Ok(entries)
}

fn read_form_string<'dw>(
    dwarf: &'dw Dwarf,
    cu: CuId,
    cursor: &mut Cursor<'_>,
    form: u64,
) -> Result<&'dw str> {
    match form {
        DW_FORM_string => {
            let start = cursor.position();
            cursor.cstr();
            Ok(dwarf.str_at(".debug_line", start))
        }
        DW_FORM_strp => Ok(dwarf.str_at(".debug_str", cursor.u32() as usize)),
        DW_FORM_line_strp => Ok(dwarf.str_at(".debug_line_str", cursor.u32() as usize)),
        DW_FORM_strx => Ok(dwarf.resolve_str_index(cu, cursor.uleb128())),
        DW_FORM_strx1 => Ok(dwarf.resolve_str_index(cu, u64::from(cursor.u8()))),
        DW_FORM_strx2 => Ok(dwarf.resolve_str_index(cu, u64::from(cursor.u16()))),
        DW_FORM_strx3 => Ok(dwarf.resolve_str_index(cu, u64::from(cursor.u24()))),
        DW_FORM_strx4 => Ok(dwarf.resolve_str_index(cu, u64::from(cursor.u32()))),
        other => Err(Error::new(format!(
            "Unsupported string form in line table header: {other:#x}"
        ))),
    }
}

fn read_form_int(cursor: &mut Cursor<'_>, form: u64) -> Result<u64> {
    match form {
        DW_FORM_data1 => Ok(u64::from(cursor.u8())),
        DW_FORM_data2 => Ok(u64::from(cursor.u16())),
        DW_FORM_data4 => Ok(u64::from(cursor.u32())),
        DW_FORM_data8 => Ok(cursor.u64()),
        DW_FORM_udata => Ok(cursor.uleb128()),
        other => Err(Error::new(format!(
            "Unsupported integer form in line table header: {other:#x}"
        ))),
    }
}
