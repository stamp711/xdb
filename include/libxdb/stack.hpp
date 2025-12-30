#pragma once

#include <cstdint>
#include <libxdb/dwarf/die.hpp>

namespace xdb {

class target;

class stack {
   public:
    stack(target& target) : target_(&target) {}

    auto get_target() const -> const target& { return *target_; }
    auto inline_height() const -> uint32_t { return inline_height_; }

    /// Calculate and set the inline height to the max possible inline height on current pc.
    void reset_inline_height();

    /// Get the inline stack at the current pc.
    ///
    /// @return A vector of die objects representing the inline stack at the current pc, with the outermost function
    ///         (which itself is not inlined) at the beginning.
    auto inline_stack_at_pc() -> std::vector<die>;

    void simulate_inlined_step_in() { --inline_height_; }

   private:
    target* target_;
    // std::vector<frame> frames_;
    uint32_t inline_height_ = 0;
};

}  // namespace xdb
