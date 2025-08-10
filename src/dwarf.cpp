#include <libxdb/detail/dwarf.h>

#include <cstddef>
#include <libxdb/dwarf.hpp>
#include <libxdb/elf.hpp>
#include <libxdb/error.hpp>
#include <memory>

namespace {

std::unordered_map<std::uint64_t, xdb::abbrev> parse_abbrev_table(const xdb::elf& elf, std::size_t byte_offset) {
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
            auto attr_type = dw_attr_type_t{cur.get_uleb128()};
            auto attr_form = dw_form_t{cur.get_uleb128()};
            if (attr_type == dw_attr_type_t::DW_AT_end) break;  // {0, 0} marks end of the attributes

            if (attr_form == dw_form_t::DW_FORM_implicit_const) {
                // There's a implicit constant value in SLEB128 format
                auto value = cur.get_sleb128();
                attrs.push_back({attr_type, attr_form, value});
            } else {
                attrs.push_back({attr_type, attr_form, 0});
            }
        }
        xdb::abbrev entry{.code = code, .tag = dw_tag_t{tag}, .has_children = has_children, .attrs = std::move(attrs)};
        abbrev_table.emplace(code, entry);
    }

    return abbrev_table;
}

std::unique_ptr<xdb::compile_unit> parse_compile_unit(xdb::dwarf& dwarf, xdb::cursor cursor) {
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
    (void)address_size;
    auto debug_abbrev_offset = cursor.get_u32();

    std::span<const std::byte> span = {start, sizeof(unit_length) + unit_length};
    return std::make_unique<xdb::compile_unit>(dwarf, span, debug_abbrev_offset);
}

std::vector<std::unique_ptr<xdb::compile_unit>> parse_compile_units(xdb::dwarf& dwarf,
                                                                    std::span<const std::byte> debug_info) {
    xdb::cursor cursor(debug_info);
    std::vector<std::unique_ptr<xdb::compile_unit>> compile_units;
    while (!cursor.finished()) {
        auto unit = parse_compile_unit(dwarf, cursor);
        cursor += unit->span().size_bytes();
        compile_units.push_back(std::move(unit));
    }
    return compile_units;
}

xdb::die parse_die(const xdb::compile_unit& cu, xdb::cursor cur) {
    const auto* start = cur.data();

    // Each debugging information entry begins with an unsigned LEB128 number
    // containing the abbreviation code for the entry.
    auto abbrev_code = cur.get_uleb128();

    // Debugging information entries consisting of only the abbreviation code 0
    // are considered null entries.
    if (abbrev_code == 0) {
        return xdb::die::null(cu, cur.data());
    }

    // If the DIE isn't null, we need to get the abbreviation table
    const auto& abbrev_table = cu.abbrev_table();
    const auto& abbrev = abbrev_table.at(abbrev_code);

    // The abbreviation code is followed by a series of attribute values.
    std::vector<const std::byte*> attr_locs;
    attr_locs.reserve(abbrev.attrs.size());
    for (auto attr_spec : abbrev.attrs) {
        attr_locs.push_back(cur.data());
        cur.skip_form(attr_spec.form);
    }

    // We've parsed the abbreviation code and attributes. The DIE ends here.
    const auto* next = cur.data();
    auto size = static_cast<std::size_t>(next - start);
    return xdb::die::non_null(cu, next, {start, size}, abbrev, std::move(attr_locs));
}

}  // namespace

namespace xdb {

void cursor::skip_form(dw_form_t form) {
    switch (form) {
        // Special cases - no bytes to skip
        case dw_form_t::DW_FORM_flag_present:
        case dw_form_t::DW_FORM_implicit_const:  // DWARF 5
            return;

        // Host address size dependent (8 bytes)
        case dw_form_t::DW_FORM_addr:
            *this += 8;
            return;

        // DWARF format size dependent (4 bytes for 32-bit DWARF)
        case dw_form_t::DW_FORM_ref_addr:
        case dw_form_t::DW_FORM_sec_offset:
        case dw_form_t::DW_FORM_strp:
        case dw_form_t::DW_FORM_strp_sup:   // DWARF 5
        case dw_form_t::DW_FORM_line_strp:  // DWARF 5
            *this += 4;
            return;

        // 1-byte fixed size
        case dw_form_t::DW_FORM_data1:
        case dw_form_t::DW_FORM_flag:
        case dw_form_t::DW_FORM_ref1:
        case dw_form_t::DW_FORM_addrx1:  // DWARF 5
        case dw_form_t::DW_FORM_strx1:   // DWARF 5
            *this += 1;
            return;

        // 2-byte fixed size
        case dw_form_t::DW_FORM_data2:
        case dw_form_t::DW_FORM_ref2:
        case dw_form_t::DW_FORM_addrx2:  // DWARF 5
        case dw_form_t::DW_FORM_strx2:   // DWARF 5
            *this += 2;
            return;

        // 3-byte fixed size
        case dw_form_t::DW_FORM_addrx3:  // DWARF 5
        case dw_form_t::DW_FORM_strx3:   // DWARF 5
            *this += 3;
            return;

        // 4-byte fixed size
        case dw_form_t::DW_FORM_data4:
        case dw_form_t::DW_FORM_ref4:
        case dw_form_t::DW_FORM_addrx4:    // DWARF 5
        case dw_form_t::DW_FORM_strx4:     // DWARF 5
        case dw_form_t::DW_FORM_ref_sup4:  // DWARF 5
            *this += 4;
            return;

        // 8-byte fixed size
        case dw_form_t::DW_FORM_data8:
        case dw_form_t::DW_FORM_ref8:
        case dw_form_t::DW_FORM_ref_sig8:
        case dw_form_t::DW_FORM_ref_sup8:  // DWARF 5
            *this += 8;
            return;

        // 16-byte fixed size
        case dw_form_t::DW_FORM_data16:  // DWARF 5
            *this += 16;
            return;

        // Variable size signed LEB128
        case dw_form_t::DW_FORM_sdata:
            get_sleb128();
            return;

        // Variable size unsigned LEB128
        case dw_form_t::DW_FORM_udata:
        case dw_form_t::DW_FORM_ref_udata:
        case dw_form_t::DW_FORM_strx:      // DWARF 5
        case dw_form_t::DW_FORM_addrx:     // DWARF 5
        case dw_form_t::DW_FORM_loclistx:  // DWARF 5
        case dw_form_t::DW_FORM_rnglistx:  // DWARF 5
            get_uleb128();
            return;

        // Variable size blocks - LEB128 length + data
        case dw_form_t::DW_FORM_block:
        case dw_form_t::DW_FORM_exprloc:
            *this += get_uleb128();
            return;

        // Variable size blocks - fixed length + data
        case dw_form_t::DW_FORM_block1:
            *this += get_u8();
            return;
        case dw_form_t::DW_FORM_block2:
            *this += get_u16();
            return;
        case dw_form_t::DW_FORM_block4:
            *this += get_u32();
            return;

        // Null-terminated string
        case dw_form_t::DW_FORM_string:
            get_string();
            return;

        // Special case - indirect form
        case dw_form_t::DW_FORM_indirect: {
            skip_form(dw_form_t{get_uleb128()});
            return;
        }
    }

    error::send("Unrecognized DWARF form");
}

dwarf::dwarf(const elf& parent_elf) : elf_(&parent_elf) {
    debug_info_span_ = elf_->get_section_contents(".debug_info");
    compile_units_ = parse_compile_units(*this, debug_info_span_);
}

const std::unordered_map<std::uint64_t, abbrev>& dwarf::get_abbrev_table(std::size_t byte_offset) {
    if (!abbrev_table_cache_.contains(byte_offset)) {
        auto abbrev_table = parse_abbrev_table(*elf_, byte_offset);
        auto abbrev_table_ptr =
            std::make_unique<const std::unordered_map<std::uint64_t, abbrev>>(std::move(abbrev_table));
        abbrev_table_cache_.emplace(byte_offset, std::move(abbrev_table_ptr));
    }
    return *abbrev_table_cache_.at(byte_offset);
}

die compile_unit::root() const {
    constexpr auto cu_header_size = 12;  // For 32-bit DWARF 5, see parse_compile_unit()
    cursor cur({span_.begin() + cu_header_size, span_.end()});
    return parse_die(*this, cur);
}

std::span<const std::byte> die::next_die_parse_span() const {
    const auto* start = next_;
    auto size = static_cast<std::size_t>(cu_->span().data() + cu_->span().size() - start);
    return {start, size};
}

bool die::contains(dw_attr_type_t attr) const {
    return std::ranges::any_of(abbrev_->attrs, [attr](const auto& spec) { return spec.type == attr; });
}

attr die::operator[](dw_attr_type_t attr) const {
    const auto& attr_specs = abbrev_->attrs;
    for (std::size_t i = 0; i < attr_specs.size(); ++i) {
        const auto& spec = attr_specs[i];
        if (spec.type == attr) {
            return {spec.type, spec.form, attr_locs_[i], *cu_, *this};
        }
    }
    error::send("Attribute not found");
}

die::children_range die::children() const { return die::children_range(*this); }

die::children_range::iterator::iterator(const die& die) {
    cursor next_cur({die.next_die_parse_span()});
    die_ = parse_die(*die.cu_, next_cur);
}

die::children_range::iterator& die::children_range::iterator::operator++() {
    if (!die_ || die_->is_null()) return *this;

    if (!die_->abbrev_->has_children) {
        // No children, so the immediate following DIE is the next sibling.
        cursor next_cur({die_->next_die_parse_span()});
        die_ = parse_die(*die_->cu_, next_cur);
    } else {
        // Children exist, so the first child is the next sibling.
        iterator sub_children(*die_);
        // Iterate (recursive) through the children until the null DIE
        while (!sub_children->is_null()) ++sub_children;
        // Next DIE of the null DIE is the next sibling
        cursor next_cur(sub_children->next_die_parse_span());
        die_ = parse_die(*die_->cu_, next_cur);
    }

    return *this;
}

bool die::children_range::iterator::operator==(const iterator& other) const {
    auto is_null = !die_ || die_->is_null();
    auto other_is_null = !other.die_ || other.die_->is_null();

    if (is_null && other_is_null) return true;
    if (is_null != other_is_null) return false;

    // Both are not null
    return die_->span_.data() == other.die_->span_.data();
}

template <>
file_addr attr::get<dw_form_t::DW_FORM_addr>() const {
    if (form_ != dw_form_t::DW_FORM_addr) error::send("Invalid form");
    // Create a cursor to: [beginning of attr, end of die)
    cursor cur({location_, die_->span().end().base()});
    const auto& elf = this->cu_->dwarf_info().elf_file();
    return file_addr(elf, cur.get_u64());
}

template <>
std::uint32_t attr::get<dw_form_t::DW_FORM_sec_offset>() const {
    if (form_ != dw_form_t::DW_FORM_sec_offset) error::send("Invalid form");
    // Create a cursor to: [beginning of attr, end of die)
    cursor cur({location_, die_->span().end().base()});
    return cur.get_u32();
}

}  // namespace xdb
