/// Tracks how far the debugger has virtually stepped into inlined frames at the
/// current pc. Updated by `Target` on every stop.
#[derive(Default)]
pub struct Stack {
    pub(crate) inline_height: usize,
    pub(crate) inline_stack_size: usize,
}

impl Stack {
    /// How many inlined frames are we currently above?
    pub fn inline_height(&self) -> usize {
        self.inline_height
    }

    pub fn has_inlined_frames(&self) -> bool {
        self.inline_stack_size > 1 // first item is the outermost function
    }

    /// Index of the current frame within the inline stack (0 is the outermost,
    /// non-inlined function).
    pub fn current_index(&self) -> usize {
        self.inline_stack_size - self.inline_height - 1
    }

    pub(crate) fn simulate_inlined_step_in(&mut self) {
        self.inline_height -= 1;
    }
}
