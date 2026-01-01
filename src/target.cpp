#include <cxxabi.h>

#include <cstdint>
#include <libxdb/breakpoint.hpp>
#include <libxdb/disassembler.hpp>
#include <libxdb/dwarf/line_table.hpp>
#include <libxdb/process.hpp>
#include <libxdb/register_info.hpp>
#include <libxdb/target.hpp>
#include <libxdb/types.hpp>
#include <memory>
#include <utility>

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
    t->get_process().set_target(*t);
    return t;
}

auto target::attach(pid_t pid) -> std::unique_ptr<target> {
    auto process = process::attach(pid);
    auto elf_path = std::filesystem::path("/proc") / std::to_string(pid) / "exe";
    auto elf = create_loaded_elf(*process, elf_path);
    auto t = std::unique_ptr<target>(new target(std::move(process), std::move(elf)));
    t->get_process().set_target(*t);
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
    auto& stack = this->get_stack();

    // Simulate step if we are currently in an inlined function
    if (stack.inline_height() > 0) {
        stack.simulate_inlined_step_in();
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

    stop_reason reason;

    auto orig_line = this->line_entry_at_pc();
    disassembler dis(*this->process_);
    auto& stack = this->get_stack();

    while (true) {
        if (stack.has_inlined_frames() && stack.inline_height() > 0) {
            // We are above an inlined subroutine, run to end of it
            auto inline_stack = stack.inline_stack_at_pc();
            const auto& die_to_skip = inline_stack[stack.current_index_in_inline_stack() + 1];
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

auto target::step_out() -> stop_reason {
    // If we are in inlined subroutine, run to end of it
    const auto& stack = this->get_stack();
    bool at_inline_frame = stack.has_inlined_frames() && stack.current_index_in_inline_stack() != 0;
    if (at_inline_frame) {
        const auto inline_stack = stack.inline_stack_at_pc();
        const auto& curr_frame = inline_stack[stack.current_index_in_inline_stack()];
        auto end_addr = *curr_frame.high_pc().to_virt_addr();
        return this->process_->run_until_address(end_addr);
    }

    // Otherwise, step out of current function
    //
    // Use rbp as frame pointer for now. UB if -fomit-frame-pointer.
    // TODO: do DWARF stack unwinding to determine return addr
    auto rbp = process_->get_registers().read_by_id_as<uint64_t>(register_id::rbp);
    auto return_addr = process_->read_memory_as<uint64_t>(virt_addr{rbp + 8});
    return this->process_->run_until_address(virt_addr{return_addr});
}

auto target::find_functions(const std::string& name) const -> find_functions_result {
    find_functions_result res;

    // try to find functions in DWARF debug info first
    res.dwarf_functions = elf_->get_dwarf().find_functions(name);
    // if not found, find in ELF symbols
    if (res.dwarf_functions.empty()) {
        for (const auto* sym : elf_->get_symbols_by_name(name)) {
            res.elf_functions.emplace_back(elf_.get(), sym);
        }
    }

    return res;
}

auto target ::function_name_at_address(virt_addr va) const -> std::string {
    auto ofa = va.to_file_addr(*elf_);
    if (!ofa) return "";
    auto fa = ofa.value();
    const auto* obj = fa.elf_file();

    auto func = obj->get_dwarf().function_containing_address(fa);
    if (func && func->name()) {
        return std::string{*func->name()};
    }
    const auto* elf_sym = obj->get_symbol_containing_file_addr(fa);
    if (elf_sym != nullptr && ELF64_ST_TYPE(elf_sym->st_info) == STT_FUNC) {
        auto elf_name = std::string{obj->get_string(elf_sym->st_name)};
        std::unique_ptr<char> p;
        p.reset(abi::__cxa_demangle(elf_name.c_str(), nullptr, nullptr, nullptr));
        return p ? p.get() : elf_name;
    }
    return "";
}

auto target::create_function_breakpoint(std::string function_name, bool hardware, bool internal) -> breakpoint& {
    auto bp = std::unique_ptr<function_breakpoint>(
        new function_breakpoint(*this, std::move(function_name), hardware, internal));
    return breakpoints_.push(std::move(bp));
}

auto target::create_line_breakpoint(std::filesystem::path file, std::size_t line, bool hardware, bool internal)
    -> breakpoint& {
    auto bp = std::unique_ptr<line_breakpoint>(new line_breakpoint(*this, std::move(file), line, hardware, internal));
    return breakpoints_.push(std::move(bp));
}

auto target::create_address_breakpoint(virt_addr addr, bool hardware, bool internal) -> breakpoint& {
    auto bp = std::unique_ptr<address_breakpoint>(new address_breakpoint(*this, addr, hardware, internal));
    return breakpoints_.push(std::move(bp));
}

}  // namespace xdb
