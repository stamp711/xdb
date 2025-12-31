#pragma once

#include <libxdb/dwarf/die.hpp>

namespace xdb {

class target;

class stack {
   public:
    stack(target& target) : target_(&target) {}

    auto get_target() const -> const target& { return *target_; }

    /// How many inlined frames are we currently above?
    auto inline_height() const -> size_t { return inline_height_; }
    auto current_index_in_inline_stack() const -> size_t { return inline_stack_size_ - inline_height_ - 1; }

    /// Calculate and set the inline height to the max possible inline height on current pc.
    void reset_inline_height();

    /// Get the inline stack at the current pc.
    ///
    /// @return A vector of die objects representing the inline stack at the current pc, with the outermost function
    ///         (which itself is not inlined) at the beginning. Contains of (max_inline_height + 1) frames.
    auto inline_stack_at_pc() const -> std::vector<die>;

    auto current_frame_of_inline_stack() const -> die {
        auto inline_stack = this->inline_stack_at_pc();
        return inline_stack[inline_stack.size() - inline_height_];
    }

    void simulate_inlined_step_in() { --inline_height_; }

   private:
    target* target_;
    // std::vector<frame> frames_;
    size_t inline_height_ = 0;
    size_t inline_stack_size_ = 0;
};

}  // namespace xdb
