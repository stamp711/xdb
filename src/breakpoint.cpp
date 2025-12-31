#include <libxdb/detail/dwarf.h>

#include <libxdb/breakpoint.hpp>
#include <libxdb/breakpoint_site.hpp>
#include <libxdb/target.hpp>
#include <libxdb/types.hpp>

namespace {

auto get_next_id() -> int32_t {
    static xdb::breakpoint_site::id_type current_id = 0;
    return ++current_id;
}

}  // namespace

namespace xdb {

breakpoint::breakpoint(target& tgt, bool is_hardware, bool is_internal)
    : target_(&tgt), is_hardware_(is_hardware), is_internal_(is_internal) {
    id_ = is_internal_ ? -1 : get_next_id();
}

void breakpoint::enable() {
    if (!is_enabled_) {
        is_enabled_ = true;
        breakpoint_sites_.for_each([](breakpoint_site& site) -> void { site.enable(); });
    }
}

void breakpoint::disable() {
    if (is_enabled_) {
        is_enabled_ = false;
        breakpoint_sites_.for_each([](breakpoint_site& site) -> void { site.disable(); });
    }
}

void function_breakpoint::resolve() {
    auto funcs = target_->find_functions(function_name_);

    for (const auto& die : funcs.dwarf_functions) {
        if (die.contains(DW_AT_low_pc) || die.contains(DW_AT_ranges)) {
            file_addr addr;
            if (die.abbreviation().tag == DW_TAG_inlined_subroutine) {
                // inlined function has no prologue, so we use low_pc as breakpoint address
                addr = die.low_pc();
            } else {
                // not a inlined function, we use the second line entry address to skip the prologue
                auto line = die.cu().line_table().get_entry_by_address(die.low_pc());
                addr = (++line)->address;
            }
            auto va = addr.to_virt_addr().value();
            if (!breakpoint_sites_.contains_address(va)) {
                auto& bp_site = target_->get_process().create_breakpoint_site(*this, next_site_id_++, va, is_hardware_,
                                                                              is_internal_);
                breakpoint_sites_.push(&bp_site);
                if (is_enabled_) bp_site.enable();
            }
        }
    }

    for (auto [elf, sym] : funcs.elf_functions) {
        auto va = file_addr(*elf, sym->st_value).to_virt_addr().value();
        if (!breakpoint_sites_.contains_address(va)) {
            auto& bp_site =
                target_->get_process().create_breakpoint_site(*this, next_site_id_++, va, is_hardware_, is_internal_);
            breakpoint_sites_.push(&bp_site);
            if (is_enabled_) bp_site.enable();
        }
    }
}

void line_breakpoint::resolve() {
    for (const auto& cu : target_->get_elf().get_dwarf().compile_units()) {
        for (auto line_entry : cu->line_table().get_entries_by_line(file_, line_)) {
            auto inline_stack =
                line_entry->address.elf_file()->get_dwarf().inline_stack_at_address(line_entry->address);
            auto no_inline_stack = inline_stack.size() == 1;
            if (no_inline_stack && inline_stack[0].low_pc() == line_entry->address) {
                // skip the prologue
                ++line_entry;
            }

            auto va = line_entry->address.to_virt_addr().value();
            if (!breakpoint_sites_.contains_address(va)) {
                auto& bp_site = target_->get_process().create_breakpoint_site(*this, next_site_id_++, va, is_hardware_,
                                                                              is_internal_);
                breakpoint_sites_.push(&bp_site);
                if (is_enabled_) bp_site.enable();
            }
        }
    }
}

void address_breakpoint::resolve() {
    if (breakpoint_sites_.empty()) {
        auto& bp_site =
            target_->get_process().create_breakpoint_site(*this, next_site_id_++, address_, is_hardware_, is_internal_);
        breakpoint_sites_.push(&bp_site);
        if (is_enabled_) bp_site.enable();
    }
}

}  // namespace xdb
