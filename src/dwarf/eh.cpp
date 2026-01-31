#include <libxdb/detail/dwarf.h>

#include <cstdint>
#include <libxdb/dwarf/cursor.hpp>
#include <libxdb/dwarf/eh.hpp>
#include <libxdb/elf.hpp>
#include <libxdb/error.hpp>
#include <libxdb/types.hpp>

namespace {

auto parse_eh_frame_pointer_with_base(xdb::cursor& cur, uint8_t encoding, uint64_t base) -> uint64_t {
    switch (encoding & 0x0F) {
        case DW_EH_PE_absptr:
            return base + cur.get_u64();
        case DW_EH_PE_uleb128:
            return base + cur.get_uleb128();
        case DW_EH_PE_udata2:
            return base + cur.get_u16();
        case DW_EH_PE_udata4:
            return base + cur.get_u32();
        case DW_EH_PE_udata8:
            return base + cur.get_u64();
        case DW_EH_PE_sleb128:
            return (uint64_t)((int64_t)(base) + cur.get_sleb128());
        case DW_EH_PE_sdata2:
            return (uint64_t)((int64_t)base + cur.get_i16());
        case DW_EH_PE_sdata4:
            return (uint64_t)((int64_t)base + cur.get_i32());
        case DW_EH_PE_sdata8:
            return (uint64_t)((int64_t)base + cur.get_i64());
        default:
            xdb::error::send("Unknown EH pointer encoding");
    }
}

auto parse_eh_frame_pointer([[maybe_unused]] const xdb::elf& elf, xdb::cursor& cur, uint8_t encoding, uint64_t pc,
                            uint64_t text_section_start, uint64_t data_section_start, uint64_t func_start) -> uint64_t {
    // https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html
    uint64_t base = 0;
    switch (encoding & 0xF0) {
        case DW_EH_PE_absptr:
            base = 0;
            break;
        case DW_EH_PE_pcrel:
            base = pc;
            break;
        case DW_EH_PE_textrel:
            base = text_section_start;
            break;
        case DW_EH_PE_datarel:
            base = data_section_start;
            break;
        case DW_EH_PE_funcrel:
            base = func_start;
            break;
        default:
            xdb::error::send("Unknown EH pointer base encoding");
    }

    return parse_eh_frame_pointer_with_base(cur, encoding, base);
}

/// Parse CIE from cursor
auto parse_cie(xdb::cursor cur) -> xdb::call_frame_information::common_information_entry {
    const auto* start = cur.data();

    uint32_t raw_length = cur.get_u32();
    if (raw_length == 0xFFFFFFFF) xdb::error::send("Extended length is not handled");
    uint32_t length = raw_length + sizeof(uint32_t);

    auto id = cur.get_u32();
    if (id != 0) xdb::error::send("CIE ID should be 0");
    auto version = cur.get_u8();

    if (version != 1 && version != 3 && version != 4) {
        xdb::error::send("Invalid CIE version");
    }

    auto augmentation = cur.get_string();

    if (!augmentation.empty() && augmentation[0] != 'z') {
        xdb::error::send("Invalid CIE augmentation");
    }

    if (version == 4) {
        auto address_size = cur.get_u8();
        if (address_size != 8) xdb::error::send("Invalid address size");
        auto segment_size = cur.get_u8();
        if (segment_size != 0) xdb::error::send("Invalid segment size");
    }

    auto code_alignment_factor = cur.get_uleb128();
    auto data_alignment_factor = cur.get_sleb128();

    [[maybe_unused]]
    auto return_address_register = version == 1 ? cur.get_u8() : cur.get_uleb128();

    uint8_t fde_pointer_encoding = DW_EH_PE_udata8 | DW_EH_PE_absptr;

    // See LSB 10.6.1.1.1 Augmentation String Format
    for (auto c : augmentation) {
        switch (c) {
            case 'z':  // augmentation data length
                cur.get_uleb128();
                break;
            case 'R':  // FDE pointer encoding
                fde_pointer_encoding = cur.get_u8();
                break;
            case 'L':  // LSDA pointer encoding
                cur.get_u8();
                break;
            case 'P': {  // eh_personality
                uint8_t encoding = cur.get_u8();
                parse_eh_frame_pointer_with_base(cur, encoding, 0);
                break;
            }
            default:
                xdb::error::send("Unknown CIE augmentation");
        }
    }

    auto instructions = std::span(cur.data(), start + length);

    return {.length = length,
            .code_alignment_factor = code_alignment_factor,
            .data_alignment_factor = data_alignment_factor,
            .fde_has_augmentation = !augmentation.empty(),
            .fde_pointer_encoding = fde_pointer_encoding,
            .instructions = instructions};
}

auto parse_fde(const xdb::call_frame_information& cfi, xdb::cursor cur)
    -> xdb::call_frame_information::frame_description_entry {
    const auto& elf = cfi.dwarf_info().elf_file();
    const auto* start = cur.data();

    // Length
    uint32_t raw_length = cur.get_u32();  // does not include length field itself
    if (raw_length == 0xFFFFFFFF) xdb::error::send("Extended length is not handled");
    uint32_t length = raw_length + sizeof(uint32_t);

    // CIE pointer
    auto current_offset = elf.data_pointer_as_file_offset(cur.data());
    xdb::file_offset cie_offset = current_offset - static_cast<std::uint64_t>(cur.get_i32());
    const auto& cie = cfi.get_cie(cie_offset);

    // Initial Location - encoding specified by CIE
    auto text_section_start =
        elf.get_section_start_file_addr(".text").transform([](auto fa) -> auto { return fa.addr(); }).value();
    auto initial_location_addr =
        parse_eh_frame_pointer(elf, cur, cie.fde_pointer_encoding, current_offset.offset(), text_section_start, 0, 0);
    auto initial_location = xdb::file_addr(elf, initial_location_addr);

    // Address Range
    auto address_range = parse_eh_frame_pointer_with_base(cur, cie.fde_pointer_encoding, 0);

    // Augmentation Data
    // Can only contain LSDA, ignore for now.
    if (cie.fde_has_augmentation) {
        auto augmentation_data_length = cur.get_uleb128();
        cur += augmentation_data_length;
    }

    auto instructions = std::span(cur.data(), start + length);

    return {.length = length,
            .cie = &cie,
            .initial_location = initial_location,
            .address_range = address_range,
            .instructions = instructions};
}

}  // namespace

namespace xdb {

auto call_frame_information::get_cie(file_offset foff) const -> const common_information_entry& {
    auto offset = foff.offset();
    if (auto f = cie_map_.find(offset); f != cie_map_.end()) return f->second;

    auto section = foff.elf_file()->get_section_contents(".eh_frame");

    // Parse from cursor [offset, section end)
    const auto* cursor_start = foff.as_data_pointer();
    const auto* cursor_end = section.end().base();
    auto cie = parse_cie(cursor({cursor_start, cursor_end}));

    return cie_map_.emplace(offset, cie).first->second;
}

}  // namespace xdb
