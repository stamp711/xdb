#include <libxdb/detail/dwarf.h>

#include <libxdb/dwarf/compile_unit.hpp>
#include <libxdb/dwarf/cursor.hpp>
#include <libxdb/dwarf/dwarf.hpp>
#include <libxdb/dwarf/line_table.hpp>
#include <libxdb/error.hpp>

#include "util.hpp"

namespace xdb {

auto line_table::initial_state() const -> entry { return {default_is_stmt_}; }

auto line_table::begin() const -> iterator { return iterator(*this); }

auto line_table::end() const -> iterator { return {}; }

auto line_table::get_entry_by_address(file_addr address) const -> iterator {
    auto it = this->begin();
    if (it == end()) return it;

    auto next = it;
    next++;

    while (next != end()) {
        if (it->address <= address && address < next->address && !it->end_sequence) return it;
        it = next;
        next++;
    }
    return end();
}

auto line_table::get_entries_by_line(const std::filesystem::path& path, uint64_t line) const -> std::vector<iterator> {
    std::vector<iterator> res;

    for (auto it = this->begin(); it != this->end(); ++it) {
        if (it->line == line) {
            if ((path.is_absolute() && it->file_entry->path == path) ||
                (path.is_relative() && path_ends_in(it->file_entry->path, path))) {
                res.push_back(it);
            }
        }
    }

    return res;
}

auto line_table::iterator::operator++() -> iterator& {
    if (pos_ == table_->data_.end().base()) {
        pos_ = nullptr;
        return *this;
    }

    while (!execute_instruction_());  // until emitted

    current_.file_entry = &table_->file_names_[current_.file - 1];
    return *this;
}

auto line_table::iterator::execute_instruction_() -> bool {
    bool emitted = false;

    cursor cur({pos_, table_->data_.end().base()});
    auto opcode = cur.get_u8();

    // P.152: Line Number Program Instructions
    if (opcode >= table_->opcode_base_) {
        // P.160 special opcodes
        //
        // Most of the instructions in a line number program are special opcodes.
        // Their purpose is to efficiently encode address and line changes.
        // See P.322 for a example special opcode encoding table.
        uint8_t adjusted_opcode = opcode - table_->opcode_base_;

        registers_.address += adjusted_opcode / table_->line_range_;

        int64_t line_delta = table_->line_base_ + (adjusted_opcode % table_->line_range_);
        auto line = static_cast<int64_t>(registers_.line) + line_delta;
        if (line < 0) error::send("line register becomes negative");
        registers_.line = static_cast<uint64_t>(line);

        current_ = registers_;
        emitted = true;

        registers_.basic_block = false;
        registers_.prologue_end = false;
        registers_.epilogue_begin = false;
        registers_.discriminator = 0;

    } else if (opcode > 0) {
        // P.162: standard opcodes
        switch (static_cast<DW_LNS>(opcode)) {
            case DW_LNS_copy: {
                // The DW_LNS_copy opcode takes no operands. It appends a row to the
                // matrix using the current values of the state machine registers. Then it sets the
                // discriminator register to 0, and sets the basic_block, prologue_end and
                // epilogue_begin registers to “false.”
                current_ = registers_;
                emitted = true;

                registers_.basic_block = false;
                registers_.prologue_end = false;
                registers_.epilogue_begin = false;
                registers_.discriminator = 0;
                break;
            }
            case DW_LNS_advance_pc: {
                // The DW_LNS_advance_pc opcode takes a single unsigned LEB128 operand
                // as the operation advance and modifies the address and op_index registers as
                // specified in Section 6.2.5.1 on page 160.
                //
                // We only support minimum_instruction_length and maximum_operations_per_instruction = 1
                current_.address += cur.get_uleb128();
                break;
            }
            case DW_LNS_advance_line: {
                // The DW_LNS_advance_line opcode takes a single signed LEB128 operand
                // and adds that value to the line register of the state machine.
                auto line = static_cast<int64_t>(current_.line) + cur.get_sleb128();
                if (line < 0) error::send("line register becomes negative");
                current_.line = static_cast<uint64_t>(line);
                break;
            }
            case DW_LNS_set_file: {
                current_.file = cur.get_uleb128();
                break;
            }
            case DW_LNS_set_column: {
                current_.column = cur.get_uleb128();
                break;
            }
            case DW_LNS_negate_stmt: {
                // The DW_LNS_negate_stmt opcode takes no operands. It sets the is_stmt
                // register of the state machine to the logical negation of its current value.
                current_.is_stmt = !current_.is_stmt;
                break;
            }
            case DW_LNS_set_basic_block: {
                // The DW_LNS_set_basic_block opcode takes no operands. It sets the
                // basic_block register of the state machine to “true.”
                current_.basic_block = true;
                break;
            }
            case DW_LNS_const_add_pc: {
                // The DW_LNS_const_add_pc opcode takes no operands. It advances the
                // address and op_index registers by the increments corresponding to special
                // opcode 255.
                //
                // When the line number program needs to advance the address by a small amount, it
                // can use a single special opcode, which occupies a single byte. When it needs to
                // advance the address by up to twice the range of the last special opcode, it can use
                // DW_LNS_const_add_pc followed by a special opcode, for a total of two bytes. Only if
                // it needs to advance the address by more than twice that range will it need to use both
                // DW_LNS_advance_pc and a special opcode, requiring three or more bytes.
                registers_.address += static_cast<uint64_t>((255 - table_->opcode_base_) / table_->line_range_);
                break;
            }
            case DW_LNS_fixed_advance_pc: {
                // The DW_LNS_fixed_advance_pc opcode takes a single uhalf (unencoded)
                // operand and adds it to the address register of the state machine and sets the
                // op_index register to 0. This is the only standard opcode whose operand is not
                // a variable length number. It also does not multiply the operand by the
                // minimum_instruction_length field of the header.
                //
                // Some assemblers may not be able emit DW_LNS_advance_pc or special opcodes
                // because they cannot encode LEB128 numbers or judge when the computation of a
                // special opcode overflows and requires the use of DW_LNS_advance_pc. Such
                // assemblers, however, can use DW_LNS_fixed_advance_pc instead, sacrificing
                // compression.
                registers_.address += cur.get_u16();
                break;
            }
            case DW_LNS_set_prologue_end: {
                // The DW_LNS_set_prologue_end opcode takes no operands. It sets the
                // prologue_end register to “true.”
                registers_.prologue_end = true;
                break;
            }
            case DW_LNS_set_epilogue_begin: {
                registers_.epilogue_begin = true;
                break;
            }
            case DW_LNS_set_isa: {
                // The DW_LNS_set_isa opcode takes a single unsigned LEB128 operand and
                // stores that value in the isa register of the state machine.
                //
                // We ignore the isa because we only support x86_64
                [[maybe_unused]]
                auto isa = cur.get_u8();
                break;
            }
            default: {
                error::send(std::format("Unexpected standard opcode: {}", opcode));
                break;
            }
        }

    } else {  // opcode == 0
        // P.164: extended opcodes
        [[maybe_unused]] auto size = cur.get_uleb128();
        auto extended_opcode = cur.get_u8();
        switch (static_cast<DW_LNE>(extended_opcode)) {
            case DW_LNE_end_sequence: {
                registers_.end_sequence = true;
                current_ = registers_;
                emitted = true;

                registers_ = table_->initial_state();
                break;
            }
            case DW_LNE_set_address: {
                registers_.address = {table_->cu().dwarf_info().elf_file(), cur.get_u64()};
                break;
            }
            case DW_LNE_define_file: {
                error::send("DW_LNE_define_file is deprecated in DWARF 5");
                break;
            }
            case DW_LNE_set_discriminator: {
                registers_.discriminator = cur.get_uleb128();
                break;
            }
            default: {
                error::send(std::format("Unexpected or unsupported extended opcode: {}", extended_opcode));
                break;
            }
        }
    }

    pos_ = cur.data();
    return emitted;
}

}  // namespace xdb
