use crate::dwarf::cfi::{CfaRule, RegisterRule, UnwindRow};
use crate::error::{Error, Result};
use crate::register_info::{RegisterId, RegisterInfo, register_info_by_dwarf_id};
use crate::registers::{RegisterValue, Registers};

/// Tracks how far the debugger has virtually stepped into inlined frames at the
/// current pc. Updated by `Target` on every stop.
#[derive(Default)]
pub struct Stack {
    inline_stack_size: usize,
    inline_height: usize,
}

impl Stack {
    /// How many inlined frames are we currently above?
    pub fn inline_height(&self) -> usize {
        self.inline_height
    }
    pub fn has_inline_frames(&self) -> bool {
        self.inline_stack_size > 1 // first item is the outermost function
    }
    /// Index of the current frame within the inline stack (0 is the outermost,
    /// non-inlined function).
    pub fn current_inline_index(&self) -> usize {
        self.inline_stack_size - self.inline_height - 1
    }
    pub(crate) fn simulate_inline_step_in(&mut self) {
        self.inline_height -= 1;
    }
    pub(crate) fn reset_inline_stack(&mut self, inline_stack_size: usize, inline_height: usize) {
        self.inline_height = inline_height;
        self.inline_stack_size = inline_stack_size;
    }
}

/// Apply `row` to the current frame's `current` registers, returning the
/// caller's registers. `read` reads 8 bytes of inferior memory at an address,
/// used by the `Offset` rule.
#[expect(dead_code)]
pub(crate) fn unwind_registers(
    current: &Registers,
    row: &UnwindRow,
    read: impl Fn(u64) -> Result<u64>,
) -> Result<Registers> {
    let mut unwond = current.clone();

    let rinfo = |dwarf_id: u64| -> Result<&'static RegisterInfo> {
        i32::try_from(dwarf_id)
            .ok()
            .and_then(register_info_by_dwarf_id)
            .ok_or_else(|| Error::new(format!("Cannot find register info for dwarf id {dwarf_id}")))
    };

    let cfa = {
        match row.cfa_rule {
            CfaRule::RegisterAndOffset { register, offset } => current
                .read_as::<u64>(rinfo(register)?)?
                .wrapping_add_signed(offset),
        }
    };

    unwond.write(RegisterId::rsp, RegisterValue::U64(cfa))?;

    for (dwarf_id, rule) in &row.register_rules {
        let reg = rinfo(*dwarf_id)?;
        let value = {
            match rule {
                RegisterRule::Undefined => None,
                RegisterRule::Register(r) => Some(current.read(rinfo(*r)?)?),
                RegisterRule::SameValue => continue,
                RegisterRule::Offset(o) => {
                    Some(RegisterValue::U64(read(cfa.wrapping_add_signed(*o))?))
                }
                RegisterRule::ValOffset(o) => Some(RegisterValue::U64(cfa.wrapping_add_signed(*o))),
            }
        };
        match value {
            None => unwond.set_undefined(reg),
            Some(val) => unwond.write(reg, val)?,
        }
    }

    Ok(unwond)
}
