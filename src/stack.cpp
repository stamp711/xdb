#include <libxdb/detail/dwarf.h>

#include <libxdb/error.hpp>
#include <libxdb/stack.hpp>
#include <libxdb/target.hpp>
#include <ranges>

namespace xdb {

void stack::reset_inline_height() {
    auto inline_stack = this->inline_stack_at_pc();
    inline_height_ = 0;
    auto fpc = target_->get_pc_file_address();

    // Increment the inline height for each function beginning at the current PC
    // TODO: should we count the DW_TAG_subprogram? Remember to check this when implementing bt.
    for (auto& die : inline_stack | std::views::reverse) {
        if (die.abbreviation().tag != DW_TAG_inlined_subroutine || die.low_pc() != fpc) break;
        ++inline_height_;
    }
}

auto stack::inline_stack_at_pc() -> std::vector<die> {
    auto pc = target_->get_pc_file_address();
    if (!pc) return {};
    return pc->elf_file()->get_dwarf().inline_stack_at_address(*pc);
}

}  // namespace xdb
