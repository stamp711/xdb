#![expect(dead_code)]

use crate::VirtAddr;
use crate::dwarf::cfi::{CfaRule, RegisterRule, UnwindTableRow};
use crate::dwarf::die::DieHandle;
use crate::dwarf::line_table::SourceLocation;
use crate::error::{Error, Result};
use crate::register_info::{RegisterId, RegisterInfo, register_info_by_dwarf_id};
use crate::registers::{RegisterValue, Registers};

/// Updated by `Target` on every stop.
#[derive(Default)]
pub struct Stack {
    /// Inline + non-inline frames, in innermost => outermost order.
    /// The first `inline_stack_size` frames are the inline stack.
    frames: Vec<Frame>,

    /// Total number of inline frames.
    inline_frames_count: usize,

    /// Tracks how many inline frames we are currently above.
    /// 0 means inside the most inlined frame.
    /// As the user steps into inner inlined frames, this is decreased.
    /// Reset on each stop to the number of inlined functions beginning at the pc.
    ///
    /// In other words, frames[inline_height] is the "innermost, active" frame in the execution state.
    inline_height: usize,

    /// The current frame index being explored, starting from frames[inline_height].
    /// TODO: move it out of `Stack`.
    exploration_offset: usize,
}

impl Stack {
    /// How many inlined frames is the (virtual) execution state above?
    pub fn inline_height(&self) -> usize {
        self.inline_height
    }
    pub fn inline_frames_count(&self) -> usize {
        self.inline_frames_count
    }
    pub fn has_inline_frames(&self) -> bool {
        self.inline_frames_count > 1 // first item is the outermost function
    }
    /// Index of the current frame within the inline stack (0 is the outermost, non-inlined function).
    /// TODO: this feels leaky.
    pub fn current_inline_index(&self) -> usize {
        self.inline_frames_count - self.inline_height - 1
    }
    pub fn simulate_inline_step_in(&mut self) {
        self.inline_height -= 1;
    }
    pub fn reset_inline_stack(&mut self, inline_stack_size: usize, inline_height: usize) {
        self.inline_height = inline_height;
        self.inline_frames_count = inline_stack_size;
    }
}

impl Stack {
    pub fn frames(&self) -> &[Frame] {
        &self.frames[self.inline_height..]
    }

    pub fn up(&mut self) {
        if self.exploration_offset + self.inline_height + 1 >= self.frames.len() {
            panic!("up() called when already at the outermost frame");
        }
        self.exploration_offset += 1;
    }

    pub fn down(&mut self) {
        if self.exploration_offset == 0 {
            panic!("down() called when already at the innermost frame");
        }
        self.exploration_offset -= 1;
    }

    // TODO: I don't like the below methods being coupled here.

    pub fn current_explored_frame(&self) -> &Frame {
        &self.frames[self.inline_height + self.exploration_offset]
    }

    pub fn current_explored_frame_regs(&self) -> &Registers {
        &self.current_explored_frame().regs
    }
}

/// A frame entry in the backtrace.
pub struct Frame {
    inlined: bool,
    /// Live pc for innermost frame, or the return address for outer frames.
    pc: VirtAddr,
    func_die: Option<DieHandle>,
    location: Option<SourceLocation>,
    regs: Registers,
}

impl Frame {
    pub fn new(
        inlined: bool,
        pc: VirtAddr,
        func_die: Option<DieHandle>,
        location: Option<SourceLocation>,
        regs: Registers,
    ) -> Self {
        Self {
            inlined,
            pc,
            func_die,
            location,
            regs,
        }
    }
}

/// Apply `row` to the current frame's `current` registers, returning the
/// caller's registers. `read` reads 8 bytes of inferior memory at an address,
/// used by the `Offset` rule.
pub(crate) fn unwind_registers(
    current: &Registers,
    row: &UnwindTableRow,
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
