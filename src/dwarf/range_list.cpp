#include <libxdb/detail/dwarf.h>

#include <algorithm>
#include <libxdb/dwarf/compile_unit.hpp>
#include <libxdb/dwarf/cursor.hpp>
#include <libxdb/dwarf/dwarf.hpp>
#include <libxdb/dwarf/range_list.hpp>
#include <libxdb/error.hpp>

namespace xdb {

auto range_list::begin() const -> range_list::iterator { return {*cu_, data_, base_address_}; }

auto range_list::end() const -> range_list::iterator { return {}; }

auto range_list::contains(file_addr addr) const -> bool {
    return std::ranges::any_of(*this, [addr](auto& ent) -> bool { return ent.contains(addr); });
}

range_list::iterator::iterator(const compile_unit& cu, std::span<const std::byte> data, file_addr base_address)
    : cu_(&cu), data_(data), base_address_(base_address), pos_(data.data()) {
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
                error::send("DW_RLE_base_addressx unimplemented");  // TODO
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
                pos_ = cur.data();
                yield = true;
                break;
            }

            case DW_RLE_base_address: {
                base_address_ = file_addr(elf, cur.get_u64());
                pos_ = cur.data();
                yield = false;
                break;
            }

            case DW_RLE_start_end: {
                current_.low = file_addr(elf, cur.get_u64());
                current_.high = file_addr(elf, cur.get_u64());
                pos_ = cur.data();
                yield = true;
                break;
            }

            case DW_RLE_start_length: {
                current_.low = base_address_ + cur.get_u64();
                current_.high = current_.low + cur.get_uleb128();
                pos_ = cur.data();
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
