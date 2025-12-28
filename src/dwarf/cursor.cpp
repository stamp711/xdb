#include <libxdb/detail/dwarf.h>

#include <libxdb/dwarf/cursor.hpp>
#include <libxdb/error.hpp>

namespace xdb {

void cursor::skip_form(uint64_t form) {
    switch (static_cast<DW_FORM>(form)) {
        // Special cases - no bytes to skip
        case DW_FORM_flag_present:
        case DW_FORM_implicit_const:  // DWARF 5
            return;

        // Host address size dependent (8 bytes)
        case DW_FORM_addr:
            *this += 8;
            return;

        // DWARF format size dependent (4 bytes for 32-bit DWARF)
        case DW_FORM_ref_addr:
        case DW_FORM_sec_offset:
        case DW_FORM_strp:
        case DW_FORM_strp_sup:   // DWARF 5
        case DW_FORM_line_strp:  // DWARF 5
            *this += 4;
            return;

        // 1-byte fixed size
        case DW_FORM_data1:
        case DW_FORM_flag:
        case DW_FORM_ref1:
        case DW_FORM_addrx1:  // DWARF 5
        case DW_FORM_strx1:   // DWARF 5
            *this += 1;
            return;

        // 2-byte fixed size
        case DW_FORM_data2:
        case DW_FORM_ref2:
        case DW_FORM_addrx2:  // DWARF 5
        case DW_FORM_strx2:   // DWARF 5
            *this += 2;
            return;

        // 3-byte fixed size
        case DW_FORM_addrx3:  // DWARF 5
        case DW_FORM_strx3:   // DWARF 5
            *this += 3;
            return;

        // 4-byte fixed size
        case DW_FORM_data4:
        case DW_FORM_ref4:
        case DW_FORM_addrx4:    // DWARF 5
        case DW_FORM_strx4:     // DWARF 5
        case DW_FORM_ref_sup4:  // DWARF 5
            *this += 4;
            return;

        // 8-byte fixed size
        case DW_FORM_data8:
        case DW_FORM_ref8:
        case DW_FORM_ref_sig8:
        case DW_FORM_ref_sup8:  // DWARF 5
            *this += 8;
            return;

        // 16-byte fixed size
        case DW_FORM_data16:  // DWARF 5
            *this += 16;
            return;

        // Variable size signed LEB128
        case DW_FORM_sdata:
            get_sleb128();
            return;

        // Variable size unsigned LEB128
        case DW_FORM_udata:
        case DW_FORM_ref_udata:
        case DW_FORM_strx:      // DWARF 5
        case DW_FORM_addrx:     // DWARF 5
        case DW_FORM_loclistx:  // DWARF 5
        case DW_FORM_rnglistx:  // DWARF 5
            get_uleb128();
            return;

        // Variable size blocks - LEB128 length + data
        case DW_FORM_block:
        case DW_FORM_exprloc:
            *this += get_uleb128();
            return;

        // Variable size blocks - fixed length + data
        case DW_FORM_block1:
            *this += get_u8();
            return;
        case DW_FORM_block2:
            *this += get_u16();
            return;
        case DW_FORM_block4:
            *this += get_u32();
            return;

        // Null-terminated string
        case DW_FORM_string:
            get_string();
            return;

        // Special case - indirect form
        case DW_FORM_indirect: {
            skip_form(get_uleb128());
            return;
        }

        default:
            error::send("Unrecognized DWARF form");
    }
}
}  // namespace xdb
