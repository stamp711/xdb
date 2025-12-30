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
    if (stack_.inline_height() > 0) {
        stack_.simulate_inlined_step_in();
        return {process_state::stopped, SIGTRAP, trap_type::single_step};
    }

    auto orig_line = this->line_entry_at_pc();
    while (true) {
        auto reason = process_->step_instruction();  // at least step a single instruction

        if (!reason.is_step()) return reason;  // if stopped not because of step, return early

        auto line = this->line_entry_at_pc();

        // no line table entry for current pc
        if (line == line_table::iterator{} /* end */) break;

        // line entry changed, and is not a special end-of-sequence entry
        if (line != orig_line && !line->end_sequence) break;
    }

    // Step over the function prologue if needed
    auto pc = get_pc_file_address();
    if (pc) {
        auto func = pc->elf_file()->get_dwarf().function_containing_address(*pc);
        if (func && func->low_pc() == *pc) {
            // we are at start of a function (prologue)
            auto line = line_entry_at_pc();
            if (line != line_table::iterator{} /* end */) {
                // GCC: first line table entry for a function marks the start of the prologue
                ++line;
                return this->process_->run_until_address(*line->address.to_virt_addr());
            }
        }
    }

    return {process_state::stopped, SIGTRAP, trap_type::single_step};
}

}  // namespace xdb
