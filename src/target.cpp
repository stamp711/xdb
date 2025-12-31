#include <libxdb/disassembler.hpp>
#include <libxdb/dwarf/line_table.hpp>
#include <libxdb/process.hpp>
#include <libxdb/target.hpp>
#include <libxdb/types.hpp>
#include <memory>

namespace {

auto create_loaded_elf(const xdb::process& process, const std::filesystem::path& path) -> std::unique_ptr<xdb::elf> {
    auto auxv = process.get_auxv();
    auto elf = std::make_unique<xdb::elf>(path);
    auto load_bias = auxv[AT_ENTRY] - elf->header().e_entry;
    elf->notify_load_bias(xdb::virt_addr(load_bias));
    return elf;
}

}  // namespace

namespace xdb {

auto target::launch(const std::filesystem::path& path, std::optional<int> stdout_replacement)
    -> std::unique_ptr<target> {
    auto process = process::launch(path, true, stdout_replacement);
    auto elf = create_loaded_elf(*process, path);
    auto t = std::unique_ptr<target>(new target(std::move(process), std::move(elf)));
    process->set_target(*t);
    return t;
}

auto target::attach(pid_t pid) -> std::unique_ptr<target> {
    auto process = process::attach(pid);
    auto elf_path = std::filesystem::path("/proc") / std::to_string(pid) / "exe";
    auto elf = create_loaded_elf(*process, elf_path);
    auto t = std::unique_ptr<target>(new target(std::move(process), std::move(elf)));
    process->set_target(*t);
    return t;
}

void target::notify_stop([[maybe_unused]] const xdb::stop_reason& reason) { stack_.reset_inline_height(); }

auto target::get_pc_file_address() const -> std::optional<file_addr> {
    // TODO: dynamic library support
    return process_->get_pc().to_file_addr(*elf_);
}

auto target::line_entry_at_pc() const -> line_table::iterator {
    auto pc = this->get_pc_file_address();
    if (!pc) return line_table::iterator{};
    const auto* cu = pc->elf_file()->get_dwarf().compile_unit_containing_address(*pc);
    if (cu == nullptr) return line_table::iterator{};
    return cu->line_table().get_entry_by_address(*pc);
}

auto target::step_in() -> stop_reason {
    // Simulate step if we are currently in an inlined function
    if (stack_.inline_height() > 0) {
        stack_.simulate_inlined_step_in();
        return {process_state::stopped, SIGTRAP, trap_type::single_step};
    }

    // Step until we reach a different line table entry
    auto orig_line = this->line_entry_at_pc();
    while (true) {
        auto reason = process_->step_instruction();  // at least step a single instruction

        if (!reason.is_step()) return reason;  // if stopped not because of step, return early

        auto line = this->line_entry_at_pc();
        if (line == line_table::iterator{} /* end */) break;  // no line table entry for current pc
        if (line != orig_line && !line->end_sequence) break;  // line entry changed && not end-of-sequence entry
    }

    // Step over function prologue if needed
    auto pc = this->get_pc_file_address();
    if (pc) {
        auto func = pc->elf_file()->get_dwarf().function_containing_address(*pc);
        if (func && func->low_pc() == *pc) {
            // we are at start of a function (prologue)
            auto line = this->line_entry_at_pc();
            if (line != line_table::iterator{} /* end */) {
                // GCC: first line table entry for a function marks the start of the prologue
                ++line;
                return this->process_->run_until_address(*line->address.to_virt_addr());
            }
        }
    }

    return {process_state::stopped, SIGTRAP, trap_type::single_step};
}

auto target::step_over() -> stop_reason {
    // Same as step_in, but:
    // - If we are above an inlined function, step over it
    // - If we are at a call instruction, step to the instruction immediately after the call
    // TODO: which takes priority?

    auto orig_line = this->line_entry_at_pc();
    disassembler dis(*this->process_);
    stop_reason reason;

    while (true) {
        if (this->stack_.inline_height() > 0) {
            // We are above in inlined subroutine, run to end of it
            auto inline_stack = this->stack_.inline_stack_at_pc();
            const auto& die_to_skip = inline_stack[inline_stack.size() - stack_.inline_height()];
            auto end_addr = *die_to_skip.high_pc().to_virt_addr();
            reason = this->process_->run_until_address(end_addr);
            if (!reason.is_step() || this->process_->get_pc() != end_addr) return reason;
        } else if (auto instrs = dis.disassemble(2, process_->get_pc()); instrs[0].text.starts_with("call")) {
            // We are at call instruction, run to next instruction
            // It's also ok if the callee never returns.
            auto return_addr = instrs[1].address;
            reason = this->process_->run_until_address(return_addr);
            if (!reason.is_step() || this->process_->get_pc() != return_addr) return reason;
        } else {
            // In other cases, just step to next instruction
            reason = process_->step_instruction();
            if (!reason.is_step()) return reason;
        }

        auto line = this->line_entry_at_pc();
        if (line == line_table::iterator{} /* end */) break;  // no line table entry for current pc
        if (line != orig_line && !line->end_sequence) break;  // line entry changed && not end-of-sequence entry
    }

    return reason;
}

}  // namespace xdb
