#include <libxdb/detail/dwarf.h>

#include <algorithm>
#include <libxdb/dwarf/compile_unit.hpp>
#include <libxdb/dwarf/dwarf.hpp>
#include <libxdb/elf.hpp>
#include <libxdb/error.hpp>

namespace {

auto parse_abbrev_table(const xdb::elf& elf, std::size_t byte_offset)
    -> std::unordered_map<std::uint64_t, xdb::abbrev> {
    xdb::cursor cur(elf.get_section_contents(".debug_abbrev"));
    cur += byte_offset;

    std::unordered_map<std::uint64_t, xdb::abbrev> abbrev_table;

    while (true) {
        // Parse one abbreviate entry
        auto code = cur.get_uleb128();
        if (code == 0) break;  // 0 marks end of the table
        auto tag = cur.get_uleb128();
        auto has_children = static_cast<bool>(cur.get_u8());  // encoded as u8
        std::vector<xdb::attr_spec> attrs;
        while (true) {
            auto attr_type = cur.get_uleb128();
            auto attr_form = cur.get_uleb128();
            if (attr_type == 0) break;  // {0, 0} marks end of the attributes

            if (attr_form == DW_FORM_implicit_const) {
                // There's a implicit constant value in SLEB128 format
                auto value = cur.get_sleb128();
                attrs.push_back({attr_type, attr_form, value});
            } else {
                attrs.push_back({attr_type, attr_form, 0});
            }
        }
        xdb::abbrev entry{.code = code, .tag = tag, .has_children = has_children, .attrs = std::move(attrs)};
        abbrev_table.emplace(code, entry);
    }

    return abbrev_table;
}

auto parse_compile_unit(xdb::dwarf& dwarf, xdb::cursor cursor) -> std::unique_ptr<xdb::compile_unit> {
    const auto* start = cursor.data();

    // Format ref: DWARF5.pdf 7.5.1.1
    auto unit_length = cursor.get_u32();
    if (unit_length == 0xffffffff) {
        xdb::error::send("64-bit DWARF is not supported");
    }

    auto version = cursor.get_u16();
    if (version != 5) {
        xdb::error::send("Only DWARF version 5 is supported");
    }

    auto unit_type = cursor.get_u8();
    if (unit_type != DW_UT_compile) {
        xdb::error::send("Only DWARF full compile units are supported");
    }

    auto address_size = cursor.get_u8();
    if (address_size != 8) {
        xdb::error::send("Only 64-bit addresses are supported");
    }

    auto debug_abbrev_offset = cursor.get_u32();

    std::span<const std::byte> span = {start, sizeof(unit_length) + unit_length};
    return std::make_unique<xdb::compile_unit>(dwarf, span, debug_abbrev_offset);
}

auto parse_compile_units(xdb::dwarf& dwarf, std::span<const std::byte> debug_info)
    -> std::vector<std::unique_ptr<xdb::compile_unit>> {
    xdb::cursor cursor(debug_info);
    std::vector<std::unique_ptr<xdb::compile_unit>> compile_units;
    while (!cursor.finished()) {
        auto unit = parse_compile_unit(dwarf, cursor);
        cursor += unit->span().size_bytes();
        compile_units.push_back(std::move(unit));
    }
    return compile_units;
}

}  // namespace

namespace xdb {

dwarf::dwarf(const elf& parent_elf) : elf_(&parent_elf) {
    debug_info_span_ = elf_->get_section_contents(".debug_info");
    compile_units_ = parse_compile_units(*this, debug_info_span_);
    cfi_ = parse_call_frame_information(*this);
}

auto dwarf::get_abbrev_table(std::size_t byte_offset) -> const std::unordered_map<std::uint64_t, abbrev>& {
    if (!abbrev_table_cache_.contains(byte_offset)) {
        auto abbrev_table = parse_abbrev_table(*elf_, byte_offset);
        auto abbrev_table_ptr =
            std::make_unique<const std::unordered_map<std::uint64_t, abbrev>>(std::move(abbrev_table));
        abbrev_table_cache_.emplace(byte_offset, std::move(abbrev_table_ptr));
    }
    return *abbrev_table_cache_.at(byte_offset);
}

auto dwarf::compile_unit_containing_address(file_addr address) const -> const compile_unit* {
    for (const auto& cu : compile_units_) {
        if (cu->root().contains_address(address)) {
            return cu.get();
        }
    }
    return nullptr;
}

auto dwarf::function_containing_address(file_addr address) const -> std::optional<die> {
    index_();
    for (const auto& [_name, die] : function_index_) {
        if (die.contains_address(address) && die.abbreviation().tag == DW_TAG_subprogram) {
            return die;
        }
    }
    return std::nullopt;
}

auto dwarf::find_functions(const std::string& name) const -> std::vector<die> {
    index_();
    std::vector<die> res;
    auto [begin, end] = function_index_.equal_range(name);
    for (auto& [_name, die] : std::ranges::subrange(begin, end)) {
        res.push_back(die);
    }
    return res;
}

auto dwarf::inline_stack_at_address(file_addr address) const -> std::vector<die> {
    auto func = function_containing_address(address);
    if (!func) return {};

    std::vector<die> stack;
    stack.push_back(*func);  // TODO: should we not include it?

    while (true) {
        // Recursively find inlined functions contains this address
        const auto& curr = stack.back();
        auto children_range = curr.children();
        auto f = std::ranges::find_if(children_range, [&](const auto& child) -> bool {
            return child.abbreviation().tag == DW_TAG_inlined_subroutine && child.contains_address(address);
        });
        if (f == children_range.end()) break;
        stack.push_back(*f);
    }

    return stack;
}

auto dwarf::index_() const -> void {
    if (!function_index_.empty()) return;
    for (const auto& cu : compile_units_) {
        index_die_(cu->root());
    }
}

auto dwarf::index_die_(const die& die) const -> void {
    bool is_function =
        die.abbreviation().tag == DW_TAG_subprogram || die.abbreviation().tag == DW_TAG_inlined_subroutine;
    bool has_range = die.contains(DW_AT_ranges) ||
                     (die.contains(DW_AT_low_pc) && die.contains(DW_AT_high_pc));  // to filter out indirect DIEs

    if (is_function && has_range) {
        auto name = die.name();
        if (name) function_index_.emplace(*name, die);
    }

    for (const auto& child : die.children()) {
        index_die_(child);
    }
}
}  // namespace xdb
