// #include <dwarf.h>
#include <libxdb/detail/dwarf.h>

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <libxdb/dwarf.hpp>
#include <libxdb/elf.hpp>
#include <libxdb/error.hpp>
#include <libxdb/types.hpp>
#include <memory>
#include <ranges>
#include <string_view>

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

auto parse_die(const xdb::compile_unit& cu, xdb::cursor cur) -> xdb::die {
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

// ========== impl cursor ==========

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

// ========== impl dwarf ==========

dwarf::dwarf(const elf& parent_elf) : elf_(&parent_elf) {
    debug_info_span_ = elf_->get_section_contents(".debug_info");
    compile_units_ = parse_compile_units(*this, debug_info_span_);
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
        if (die.contains_address(address) && die.abbreviation().tag == dw_tag_t::DW_TAG_subprogram) {
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

auto dwarf::index_() const -> void {
    if (!function_index_.empty()) return;
    for (const auto& cu : compile_units_) {
        index_die_(cu->root());
    }
}

auto dwarf::index_die_(const die& die) const -> void {
    bool is_function = die.abbreviation().tag == dw_tag_t::DW_TAG_subprogram ||
                       die.abbreviation().tag == dw_tag_t::DW_TAG_inlined_subroutine;
    bool has_range = die.contains(dw_attr_type_t::DW_AT_low_pc) && die.contains(dw_attr_type_t::DW_AT_high_pc);

    if (is_function && has_range) {
        auto name = die.name();
        if (name) function_index_.emplace(*name, die);
    }

    for (const auto& child : die.children()) {
        index_die_(child);
    }
}

// ========== impl compile_unit ==========

auto compile_unit::root() const -> die {
    constexpr auto cu_header_size = 12;  // For 32-bit DWARF 5, see parse_compile_unit()
    cursor cur({span_.begin() + cu_header_size, span_.end()});
    return parse_die(*this, cur);
}

// ========== impl die ==========

auto die::next_die_parse_span() const -> std::span<const std::byte> {
    const auto* start = next_;
    auto size = static_cast<std::size_t>(cu_->span().data() + cu_->span().size() - start);
    return {start, size};
}

auto die::contains(dw_attr_type_t attr) const -> bool {
    return std::ranges::any_of(abbrev_->attrs, [attr](const auto& spec) -> bool { return spec.type == attr; });
}

auto die::operator[](dw_attr_type_t att) const -> attr {
    const auto& attr_specs = abbrev_->attrs;
    for (std::size_t i = 0; i < attr_specs.size(); ++i) {
        const auto& spec = attr_specs[i];
        if (spec.type == att) {
            return {spec.type, spec.form, attr_locs_[i], *cu_};
        }
    }
    error::send("Attribute not found");
}

auto die::low_pc() const -> file_addr {
    if (this->contains(dw_attr_type_t::DW_AT_ranges)) {
        return (*this)[dw_attr_type_t::DW_AT_ranges].as_range_list().begin()->low;
    }

    if (this->contains(dw_attr_type_t::DW_AT_low_pc)) {
        return (*this)[dw_attr_type_t::DW_AT_low_pc].as_address();
    }

    error::send("DIE does not contain DW_AT_low_pc or DW_AT_ranges");
}

auto die::high_pc() const -> file_addr {
    if (this->contains(dw_attr_type_t::DW_AT_ranges)) {
        auto range_list = (*this)[dw_attr_type_t::DW_AT_ranges].as_range_list();
        auto it = range_list.begin();
        while (std::next(it) != range_list.end()) ++it;
        return it->high;  // high addr in last range
    }

    if (this->contains(dw_attr_type_t::DW_AT_high_pc)) {
        auto attr = (*this)[dw_attr_type_t::DW_AT_high_pc];

        // Per DWARF5.pdf, 2.17.2:
        // If the value of the DW_AT_high_pc is of class address, it is the address of the first location past the last
        // instruction associated with the entity; if it is of class constant, the value is an unsigned integer offset
        // which when added to the low PC gives the address of the first location past the last instruction associated
        // with the entity.

        if (attr.form() == dw_form_t::DW_FORM_addr) {
            return attr.as_address();
        }
        return low_pc() + attr.as_int();
    }

    error::send("DIE does not contain DW_AT_high_pc or DW_AT_ranges");
}

auto die::contains_address(file_addr address) const -> bool {
    if (*address.elf_file() != this->cu_->dwarf_info().elf_file()) {
        return false;
    }

    if (this->contains(dw_attr_type_t::DW_AT_ranges)) {
        return (*this)[dw_attr_type_t::DW_AT_ranges].as_range_list().contains(address);
    }

    if (this->contains(dw_attr_type_t::DW_AT_low_pc)) {
        return this->low_pc() <= address && address < this->high_pc();
    }

    return false;
}

auto die::children() const -> die::children_range { return die::children_range(*this); }

auto die::name() const -> std::optional<std::string_view> {
    // Most function DIEs encode the name of the function as a DW_AT_name attribute, but two special types of function
    // encode the name indirectly. DIEs that represent out-of-line definitions (which occur, for example, when we
    // declare a member function in a header file and define it in a source file) contain a DW_AT_specification
    // attribute that points to the DIE representing the original declaration. Also, inlined functions (those whose body
    // the compiler has copy-pasted into the body of another function) contain a DW_AT_abstract_origin attribute that
    // points to the DIE representing the copied function.

    if (this->contains(dw_attr_type_t::DW_AT_name)) {
        return (*this)[dw_attr_type_t::DW_AT_name].as_string();
    }
    if (this->contains(dw_attr_type_t::DW_AT_specification)) {
        return (*this)[dw_attr_type_t::DW_AT_specification].as_reference().name();
    }
    if (this->contains(dw_attr_type_t::DW_AT_abstract_origin)) {
        return (*this)[dw_attr_type_t::DW_AT_abstract_origin].as_reference().name();
    }
    return std::nullopt;
}

// ========== impl die::children_range && iterator ==========

die::children_range::iterator::iterator(const die& die) {
    cursor next_cur({die.next_die_parse_span()});
    die_ = parse_die(*die.cu_, next_cur);
}

auto die::children_range::iterator::operator++() -> die::children_range::iterator& {
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

auto die::children_range::iterator::operator==(const iterator& other) const -> bool {
    auto is_null = !die_ || die_->is_null();
    auto other_is_null = !other.die_ || other.die_->is_null();

    if (is_null && other_is_null) return true;
    if (is_null != other_is_null) return false;

    // Both are not null
    return die_->span_.data() == other.die_->span_.data();
}

// ========== impl attr ==========

auto attr::as_address() const -> file_addr {
    if (form_ != dw_form_t::DW_FORM_addr) error::send("Invalid form");
    // Create a cursor to: [beginning of attr, end of cu)
    cursor cur({location_, cu_->span().end().base()});
    const auto& elf = this->cu_->dwarf_info().elf_file();
    return file_addr(elf, cur.get_u64());
}

auto attr::as_section_offset() const -> std::uint32_t {
    if (form_ != dw_form_t::DW_FORM_sec_offset) error::send("Invalid form");
    // Create a cursor to: [beginning of attr, end of cu)
    cursor cur({location_, cu_->span().end().base()});
    return cur.get_u32();
}

auto attr::as_int() const -> std::uint64_t {
    // Create a cursor to: [beginning of attr, end of cu)
    cursor cur({location_, cu_->span().end().base()});
    switch (form_) {
        case dw_form_t::DW_FORM_data1:
            return cur.get_u8();
        case dw_form_t::DW_FORM_data2:
            return cur.get_u16();
        case dw_form_t::DW_FORM_data4:
            return cur.get_u32();
        case dw_form_t::DW_FORM_data8:
            return cur.get_u64();
        case dw_form_t::DW_FORM_udata:
            return cur.get_uleb128();
        default:
            error::send("Invalid integer form");
    }
}

auto attr::as_block() const -> std::span<const std::byte> {
    // Create a cursor to: [beginning of attr, end of cu)
    cursor cur({location_, cu_->span().end().base()});
    std::size_t size = 0;
    switch (form_) {
        case dw_form_t::DW_FORM_block1:
            size = cur.get_u8();
            break;
        case dw_form_t::DW_FORM_block2:
            size = cur.get_u16();
            break;
        case dw_form_t::DW_FORM_block4:
            size = cur.get_u32();
            break;
        case dw_form_t::DW_FORM_block:
            size = cur.get_uleb128();
            break;
        default:
            error::send("Invalid block form");
    }
    return {cur.data(), size};
}

auto attr::as_reference() const -> die {
    // Create a cursor to: [beginning of attr, end of cu)
    cursor cur({location_, cu_->span().end().base()});
    std::size_t offset = 0;
    switch (form_) {
        case dw_form_t::DW_FORM_ref1:
            offset = cur.get_u8();
            break;
        case dw_form_t::DW_FORM_ref2:
            offset = cur.get_u16();
            break;
        case dw_form_t::DW_FORM_ref4:
            offset = cur.get_u32();
            break;
        case dw_form_t::DW_FORM_ref8:
            offset = cur.get_u64();
            break;
        case dw_form_t::DW_FORM_ref_udata:
            offset = cur.get_uleb128();
            break;
        case dw_form_t::DW_FORM_ref_addr: {
            // Special handling
            offset = cur.get_u32();
            auto debug_info_span = cu_->dwarf_info().elf_file().get_section_contents(".debug_info");
            const std::byte* die_pos = debug_info_span.data() + offset;

            const auto& cus = cu_->dwarf_info().compile_units();
            const auto& containing_cu = *std::ranges::find_if(cus, [&](const auto& cu) -> bool {
                auto cu_span = cu->span();
                return die_pos >= cu_span.data() && die_pos < cu_span.data() + cu_span.size();
            });

            cursor ref_cursor({die_pos, containing_cu->span().end().base()});
            return parse_die(*containing_cu, ref_cursor);
        }
        default:
            error::send("Invalid reference form");
    }
    cursor ref_cursor(cu_->span().subspan(offset));
    return parse_die(*cu_, ref_cursor);
}

auto xdb::attr::as_string() const -> std::string_view {
    // Create a cursor to: [beginning of attr, end of cu)
    cursor cur({location_, cu_->span().end().base()});
    switch (form_) {
        case dw_form_t::DW_FORM_string:
            return cur.get_string();
        case dw_form_t::DW_FORM_strp: {
            auto offset = cur.get_u32();
            auto debug_str_span = cu_->dwarf_info().elf_file().get_section_contents(".debug_str");
            cursor stab_cur({debug_str_span.begin() + offset, debug_str_span.end()});
            return stab_cur.get_string();
        }
        case dw_form_t::DW_FORM_line_strp: {
            auto offset = cur.get_u32();
            auto debug_line_span = cu_->dwarf_info().elf_file().get_section_contents(".debug_line_str");
            cursor stab_cur({debug_line_span.begin() + offset, debug_line_span.end()});
            return stab_cur.get_string();
        }
        default:
            error::send("Invalid string form");
    }
}

auto xdb::attr::as_range_list() const -> xdb::range_list {
    // Per DWARF5.pdf, Page 216, get data range from .debug_rnglists
    auto section = cu_->dwarf_info().elf_file().get_section_contents(".debug_rnglists");
    cursor cur(section);

    std::uint32_t offset = 0;
    switch (form_) {
        case dw_form_t::DW_FORM_sec_offset: {
            offset = as_section_offset();
            break;
        }

        case dw_form_t::DW_FORM_rnglistx: {
            // See Range List Table spec: DWARF5.pdf, Page 242

            // P.216, this is an unsigned ULEB
            auto index = cursor({location_, cu_->span().end().base()}).get_uleb128();

            // Seek to offsets table base of this cu.
            // P.66:
            // A DW_AT_rnglists_base attribute, whose value is of class rnglistsptr. This
            // attribute points to the beginning of the offsets table (immediately following
            // the header) of the compilation unit’s contribution to the .debug_rnglists
            // section. References to range lists (using DW_FORM_rnglistx) within the
            // compilation unit are interpreted relative to this base.
            auto rnglists_base = cu_->root()[dw_attr_type_t::DW_AT_rnglists_base].as_section_offset();
            cur += rnglists_base;

            // P.198: In the body of the .debug_loclists and .debug_rnglists sections, the
            // offsets the follow the header depend on the DWARF format as follows: in the
            // 32-bit DWARF format, offsets are 4-byte unsigned integer values; in the 64-bit
            // DWARF format, they are 8-byte unsigned integers.
            cur += index * 4;

            // P.242: The contents of the i-th offset is the offset (an unsigned integer) from the
            // beginning of the offset array to the location of the ith range list.
            //
            // P.243: The DW_AT_rnglists_base attribute points to the first offset following the header.
            offset = rnglists_base + cur.get_u32();

            break;
        }

        default:
            error::send("Invalid range list form");
    }

    std::span<const std::byte> data(section.begin() + offset, section.end());

    // Per DWARF5.pdf P.53:
    // ... If there is no preceding base address entry, then the applicable base address defaults to the base address of
    // the compilation unit.
    auto root = cu_->root();
    file_addr base_address =
        root.contains(dw_attr_type_t::DW_AT_low_pc) ? root[dw_attr_type_t::DW_AT_low_pc].as_address() : file_addr{};

    return {*cu_, data, base_address};
}

// ========== impl range_list && iterator ==========

auto range_list::begin() const -> range_list::iterator { return {*cu_, data_, base_address_}; }

auto range_list::end() const -> range_list::iterator { return {}; }  // NOLINT

auto range_list::contains(file_addr addr) const -> bool {
    return std::ranges::any_of(*this, [addr](auto& ent) -> auto { return ent.contains(addr); });
}

range_list::iterator::iterator(const compile_unit& cu, std::span<const std::byte> data, file_addr base_address)
    : cu_(&cu), data_(data), base_address_(base_address) {
    ++(*this);
}

auto range_list::iterator::operator++() -> range_list::iterator& {
    const auto& elf = cu_->dwarf_info().elf_file();
    cursor cur({pos_, data_.end().base()});

    bool yield = false;
    while (!yield) {
        // Per DWARF5.pdf P. 53:
        // Each range list entry begins with a single byte identifying the kind of that entry, followed by zero or more
        // operands depending on the kind.
        auto kind = cur.get_u8();
        switch (kind) {
            case DW_RLE_end_of_list: {
                pos_ = nullptr;  // matches end() and operator==()
                yield = true;
                break;
            }

            case DW_RLE_base_addressx: {
                // ULEB128 index into .debug_addr
                xdb::error::send("DW_RLE_base_addressx unimplemented");  // TODO
                yield = false;
                break;
            }

            case DW_RLE_startx_endx: {
                // 2 ULEB128 indexes into .debug_addr
                xdb::error::send("DW_RLE_startx_endx unimplemented");  // TODO
                yield = false;
                break;
            }

            case DW_RLE_startx_length: {
                // 2 ULEB operands: 1. index into .debug_addr, 2. length of the range
                xdb::error::send("DW_RLE_startx_length unimplemented");  // TODO
                yield = false;
                break;
            }

            case DW_RLE_offset_pair: {
                current_.low = base_address_ + cur.get_uleb128();
                current_.high = base_address_ + cur.get_uleb128();
                yield = true;
                break;
            }

            case DW_RLE_base_address: {
                base_address_ = file_addr(elf, cur.get_u64());
                yield = false;
                break;
            }

            case DW_RLE_start_end: {
                current_.low = file_addr(elf, cur.get_u64());
                current_.high = file_addr(elf, cur.get_u64());
                yield = true;
                break;
            }

            case DW_RLE_start_length: {
                current_.low = base_address_ + cur.get_u64();
                current_.high = current_.low + cur.get_uleb128();
                yield = true;
                break;
            }

            default: {
                xdb::error::send("unknown range list entry kind");
                break;
            }
        }
    }

    return *this;
}

}  // namespace xdb
