use super::Dwarf;
use super::constants::*;
use super::cursor::Cursor;
use super::unit::CuId;
use crate::types::FileAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeEntry {
    pub low: FileAddr,
    pub high: FileAddr,
}

impl RangeEntry {
    pub fn contains(&self, address: FileAddr) -> bool {
        self.low <= address && address < self.high
    }
}

/// A `.debug_rnglists` range list, decoded lazily through its iterator.
pub struct RangeList<'dw> {
    dwarf: &'dw Dwarf,
    cu: CuId,
    offset: usize,
    base_address: FileAddr,
}

impl<'dw> RangeList<'dw> {
    pub(crate) fn new(dwarf: &'dw Dwarf, cu: CuId, offset: usize, base_address: FileAddr) -> Self {
        Self {
            dwarf,
            cu,
            offset,
            base_address,
        }
    }

    pub fn iter(&self) -> RangeListIter<'dw> {
        RangeListIter {
            dwarf: self.dwarf,
            cu: self.cu,
            cursor: Cursor::at(self.dwarf.section(".debug_rnglists"), self.offset),
            base_address: self.base_address,
        }
    }

    pub fn contains(&self, address: FileAddr) -> bool {
        self.iter().any(|entry| entry.contains(address))
    }
}

pub struct RangeListIter<'dw> {
    dwarf: &'dw Dwarf,
    cu: CuId,
    cursor: Cursor<'dw>,
    base_address: FileAddr,
}

impl Iterator for RangeListIter<'_> {
    type Item = RangeEntry;

    fn next(&mut self) -> Option<RangeEntry> {
        // Each entry begins with a one-byte kind, followed by operands that depend on it
        // (DWARF 5 §7.28). The `x` kinds take .debug_addr indices rather than literal addresses;
        // `offset_pair` is relative to the running base address;
        // base-address entries update that base and yield no range.
        loop {
            let kind = u64::from(self.cursor.u8());
            match kind {
                DW_RLE_end_of_list => return None,
                // ULEB128 index into .debug_addr; sets the base address.
                DW_RLE_base_addressx => {
                    self.base_address = self
                        .dwarf
                        .resolve_addr_index(self.cu, self.cursor.uleb128());
                }
                // Literal address; sets the base address.
                DW_RLE_base_address => {
                    self.base_address = FileAddr(self.cursor.u64());
                }
                // Two ULEB128 indexes into .debug_addr.
                DW_RLE_startx_endx => {
                    let low = self
                        .dwarf
                        .resolve_addr_index(self.cu, self.cursor.uleb128());
                    let high = self
                        .dwarf
                        .resolve_addr_index(self.cu, self.cursor.uleb128());
                    return Some(RangeEntry { low, high });
                }
                // .debug_addr index for the start, then a ULEB128 length.
                DW_RLE_startx_length => {
                    let low = self
                        .dwarf
                        .resolve_addr_index(self.cu, self.cursor.uleb128());
                    let high = low + self.cursor.uleb128();
                    return Some(RangeEntry { low, high });
                }
                // Two ULEB128 offsets from the current base address.
                DW_RLE_offset_pair => {
                    let low = self.base_address + self.cursor.uleb128();
                    let high = self.base_address + self.cursor.uleb128();
                    return Some(RangeEntry { low, high });
                }
                // Two literal addresses.
                DW_RLE_start_end => {
                    let low = FileAddr(self.cursor.u64());
                    let high = FileAddr(self.cursor.u64());
                    return Some(RangeEntry { low, high });
                }
                // Literal start address, then a ULEB128 length.
                DW_RLE_start_length => {
                    let low = FileAddr(self.cursor.u64());
                    let high = low + self.cursor.uleb128();
                    return Some(RangeEntry { low, high });
                }
                _ => return None,
            }
        }
    }
}
