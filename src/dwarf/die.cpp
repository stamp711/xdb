#include <libxdb/dwarf/die.hpp>

#include "parse.hpp"

#include <libxdb/detail/dwarf.h>

#include <algorithm>
#include <libxdb/dwarf/compile_unit.hpp>
#include <libxdb/dwarf/cursor.hpp>
#include <libxdb/elf.hpp>
#include <libxdb/error.hpp>

namespace xdb::detail {
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
}  // namespace xdb::detail

namespace xdb {

// ========== impl die ==========

auto die::next_die_parse_span() const -> std::span<const std::byte> {
    const auto* start = next_;
    auto size = static_cast<std::size_t>(cu_->span().data() + cu_->span().size() - start);
    return {start, size};
}

auto die::offset_in_debug_info() const -> std::size_t {
    return static_cast<std::size_t>(span_.data() - cu_->dwarf_info().debug_info().data());
}

auto die::contains(uint64_t attr) const -> bool {
    return std::ranges::any_of(abbrev_->attrs, [attr](const auto& spec) -> bool { return spec.type == attr; });
}

auto die::operator[](uint64_t att) const -> attr {
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
    if (this->contains(DW_AT_ranges)) {
        return (*this)[DW_AT_ranges].as_range_list().begin()->low;
    }

    if (this->contains(DW_AT_low_pc)) {
        return (*this)[DW_AT_low_pc].as_address();
    }

    error::send("DIE does not contain DW_AT_low_pc or DW_AT_ranges");
}

auto die::high_pc() const -> file_addr {
    if (this->contains(DW_AT_ranges)) {
        auto range_list = (*this)[DW_AT_ranges].as_range_list();
        auto it = range_list.begin();
        while (std::next(it) != range_list.end()) ++it;
        return it->high;  // high addr in last range
    }

    if (this->contains(DW_AT_high_pc)) {
        auto attr = (*this)[DW_AT_high_pc];

        // Per DWARF5.pdf, 2.17.2:
        // If the value of the DW_AT_high_pc is of class address, it is the address of the first location past the last
        // instruction associated with the entity; if it is of class constant, the value is an unsigned integer offset
        // which when added to the low PC gives the address of the first location past the last instruction associated
        // with the entity.

        if (attr.form() == DW_FORM_addr) {
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

    if (this->contains(DW_AT_ranges)) {
        return (*this)[DW_AT_ranges].as_range_list().contains(address);
    }

    if (this->contains(DW_AT_low_pc)) {
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

    if (this->contains(DW_AT_name)) {
        return (*this)[DW_AT_name].as_string();
    }
    if (this->contains(DW_AT_specification)) {
        return (*this)[DW_AT_specification].as_reference().name();
    }
    if (this->contains(DW_AT_abstract_origin)) {
        return (*this)[DW_AT_abstract_origin].as_reference().name();
    }
    return std::nullopt;
}

// ========== impl die::children_range && iterator ==========

die::children_range::iterator::iterator(const die& die) {
    cursor next_cur({die.next_die_parse_span()});
    die_ = detail::parse_die(*die.cu_, next_cur);
}

auto die::children_range::iterator::operator++() -> die::children_range::iterator& {
    if (!die_ || die_->is_null()) return *this;

    if (!die_->abbrev_->has_children) {
        // No children, so the immediate following DIE is the next sibling.
        cursor next_cur({die_->next_die_parse_span()});
        die_ = detail::parse_die(*die_->cu_, next_cur);
    } else {
        // Children exist, so the first child is the next sibling.
        iterator sub_children(*die_);
        // Iterate (recursive) through the children until the null DIE
        while (!sub_children->is_null()) ++sub_children;
        // Next DIE of the null DIE is the next sibling
        cursor next_cur(sub_children->next_die_parse_span());
        die_ = detail::parse_die(*die_->cu_, next_cur);
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
    if (form_ != DW_FORM_addr) error::send("Invalid form");
    // Create a cursor to: [beginning of attr, end of cu)
    cursor cur({location_, cu_->span().end().base()});
    const auto& elf = this->cu_->dwarf_info().elf_file();
    return file_addr(elf, cur.get_u64());
}

auto attr::as_section_offset() const -> std::uint32_t {
    if (form_ != DW_FORM_sec_offset) error::send("Invalid form");
    // Create a cursor to: [beginning of attr, end of cu)
    cursor cur({location_, cu_->span().end().base()});
    return cur.get_u32();
}

auto attr::as_int() const -> std::uint64_t {
    // Create a cursor to: [beginning of attr, end of cu)
    cursor cur({location_, cu_->span().end().base()});
    switch (form_) {
        case DW_FORM_data1:
            return cur.get_u8();
        case DW_FORM_data2:
            return cur.get_u16();
        case DW_FORM_data4:
            return cur.get_u32();
        case DW_FORM_data8:
            return cur.get_u64();
        case DW_FORM_udata:
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
        case DW_FORM_block1:
            size = cur.get_u8();
            break;
        case DW_FORM_block2:
            size = cur.get_u16();
            break;
        case DW_FORM_block4:
            size = cur.get_u32();
            break;
        case DW_FORM_block:
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
        case DW_FORM_ref1:
            offset = cur.get_u8();
            break;
        case DW_FORM_ref2:
            offset = cur.get_u16();
            break;
        case DW_FORM_ref4:
            offset = cur.get_u32();
            break;
        case DW_FORM_ref8:
            offset = cur.get_u64();
            break;
        case DW_FORM_ref_udata:
            offset = cur.get_uleb128();
            break;
        case DW_FORM_ref_addr: {
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
            return detail::parse_die(*containing_cu, ref_cursor);
        }
        default:
            error::send("Invalid reference form");
    }
    cursor ref_cursor(cu_->span().subspan(offset));
    return detail::parse_die(*cu_, ref_cursor);
}

auto xdb::attr::as_string() const -> std::string_view {
    // Create a cursor to: [beginning of attr, end of cu)
    cursor cur({location_, cu_->span().end().base()});
    switch (form_) {
        case DW_FORM_string:
            return cur.get_string();
        case DW_FORM_strp: {
            auto offset = cur.get_u32();
            auto debug_str_span = cu_->dwarf_info().elf_file().get_section_contents(".debug_str");
            cursor stab_cur({debug_str_span.begin() + offset, debug_str_span.end()});
            return stab_cur.get_string();
        }
        case DW_FORM_line_strp: {
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
        case DW_FORM_sec_offset: {
            offset = as_section_offset();
            break;
        }

        case DW_FORM_rnglistx: {
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
            auto rnglists_base = cu_->root()[DW_AT_rnglists_base].as_section_offset();
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
    file_addr base_address = root.contains(DW_AT_low_pc) ? root[DW_AT_low_pc].as_address() : file_addr{};

    return {*cu_, data, base_address};
}

}  // namespace xdb
