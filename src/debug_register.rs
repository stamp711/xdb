//! Encoding helpers for the x86-64 debug registers (DR0–DR3 addresses, DR7
//! control). DR7 packs, per slot `i`: an enable bit at `2*i`, a mode field at
//! `16 + 4*i`, and a size field at `18 + 4*i`.

use crate::error::{Error, Result};
use crate::types::StoppointMode;

pub(crate) const MODE_BITS_OFFSET: usize = 16;
pub(crate) const SLOT_COUNT: usize = 4;

pub(crate) fn encode_mode(mode: StoppointMode) -> u64 {
    match mode {
        StoppointMode::Execute => 0b00,
        StoppointMode::Write => 0b01,
        StoppointMode::ReadWrite => 0b11,
    }
}

pub(crate) fn decode_mode(bits: u64) -> Result<StoppointMode> {
    match bits {
        0b00 => Ok(StoppointMode::Execute),
        0b01 => Ok(StoppointMode::Write),
        0b11 => Ok(StoppointMode::ReadWrite),
        other => Err(Error::new(format!(
            "Invalid hardware stoppoint mode: {other:#b}"
        ))),
    }
}

pub(crate) fn encode_size(size: usize) -> Result<u64> {
    match size {
        1 => Ok(0b00),
        2 => Ok(0b01),
        8 => Ok(0b10),
        4 => Ok(0b11),
        other => Err(Error::new(format!(
            "Invalid hardware stoppoint size: {other}"
        ))),
    }
}

/// Returns 0/1/2/3, or an error if there's no free space.
pub(crate) fn find_free_slot(control: u64) -> Result<usize> {
    (0..SLOT_COUNT)
        .find(|i| control & (0b11 << (2 * i)) == 0)
        .ok_or_else(|| Error::new("No free hardware stoppoint register available"))
}
