#include <libxdb/detail/dwarf.h>

#include <libxdb/dwarf/compile_unit.hpp>
#include <libxdb/dwarf/cursor.hpp>
#include <libxdb/dwarf/dwarf.hpp>
#include <libxdb/elf.hpp>
#include <libxdb/error.hpp>

#include "parse.hpp"

namespace {

auto parse_line_table(const xdb::compile_unit& cu) -> std::unique_ptr<xdb::line_table> {
    if (!cu.root().contains(DW_AT_stmt_list)) return nullptr;
    auto offset = cu.root()[DW_AT_stmt_list].as_section_offset();

    auto debug_line = cu.dwarf_info().elf_file().get_section_contents(".debug_line");
    xdb::cursor cur({debug_line.begin() + offset, debug_line.end()});

    // P.154: Line Number Program header format
    auto unit_length = cur.get_u32();
    if (unit_length >= 0xfffffff0) xdb::error::send("Initial Length extension value is not supported");
    const auto* end = cur.data() + unit_length;  // not including the length field itself

    auto version = cur.get_u16();
    if (version != 5) xdb::error::send("Only version 5 is supported");

    auto address_size = cur.get_u8();
    if (address_size != 8) xdb::error::send("Unsupported address_size");

    auto segment_selector_size = cur.get_u8();
    if (segment_selector_size != 0) xdb::error::send("Unsupported segment_selector_size");

    [[maybe_unused]]
    auto header_length = cur.get_u32();

    auto minimum_instruction_length = cur.get_u8();
    if (minimum_instruction_length != 1) xdb::error::send("Unexpected minimum_instruction_length");

    auto maximum_operations_per_instruction = cur.get_u8();
    if (maximum_operations_per_instruction != 1) xdb::error::send("Unexpected maximum_operations_per_instruction");

    auto default_is_stmt = cur.get_u8();
    auto line_base = cur.get_i8();
    auto line_range = cur.get_u8();
    auto opcode_base = cur.get_u8();

    // P.162: Standard Opcodes
    auto expected_opcode_lengths = std::unordered_map<DW_LNS, uint8_t>{{DW_LNS_copy, 0},
                                                                       {DW_LNS_advance_pc, 1},
                                                                       {DW_LNS_advance_line, 1},
                                                                       {DW_LNS_set_file, 1},
                                                                       {DW_LNS_set_column, 1},
                                                                       {DW_LNS_negate_stmt, 0},
                                                                       {DW_LNS_set_basic_block, 0},
                                                                       {DW_LNS_const_add_pc, 0},
                                                                       {DW_LNS_fixed_advance_pc, 1},
                                                                       {DW_LNS_set_prologue_end, 0},
                                                                       {DW_LNS_set_epilogue_begin, 0},
                                                                       {DW_LNS_set_isa, 1}};
    for (auto i = 1; i < opcode_base; ++i) {  // It may only use a subset of standard opcodes
        if (cur.get_u8() != expected_opcode_lengths[static_cast<DW_LNS>(i)]) {
            xdb::error::send("Unexpected standard opcode length");
        }
    }

    std::vector<std::filesystem::path> dirs;
    {
        // directory_entry_format
        //
        // A sequence of directory entry format descriptions. Each description consists of a pair of ULEB128 values:
        // - A content type code (see Sections 6.2.4.1 on page 158 and 6.2.4.2 on page 159).
        // - A form code using the attribute form codes
        auto directory_entry_format_count = cur.get_u8();

        std::vector<std::pair<DW_LNCT, DW_FORM>> dir_format;
        for (auto i = 0; i < directory_entry_format_count; ++i) {
            auto content_type = static_cast<DW_LNCT>(cur.get_uleb128());
            auto form = static_cast<DW_FORM>(cur.get_uleb128());
            dir_format.emplace_back(content_type, form);
        }

        // directories
        //
        // A sequence of directory names and optional related information. Each entry
        // is encoded as described by the directory_entry_format field.
        //
        // The first entry is the current directory of the compilation. Each additional
        // path entry is either a full path name or is relative to the current directory of
        // the compilation.
        //
        // The line number program assigns a number (index) to each of the directory
        // entries in order, beginning with 0.
        //
        // Prior to DWARF Version 5, the current directory was not represented in the
        // directories field and a directory index of 0 implicitly referred to that directory as found
        // in the DW_AT_comp_dir attribute of the compilation unit debugging information
        // entry. In DWARF Version 5, the current directory is explicitly present in the
        // directories field. This is needed to support the common practice of stripping all but
        // the line number sections (.debug_line and .debug_line_str) from an executable.
        auto directories_count = cur.get_uleb128();
        for (size_t i = 0; i < directories_count; ++i) {
            std::filesystem::path path;

            // Extract dir path
            for (auto [content_type, form] : dir_format) {
                // P.158: Standard & Vecdor-defined Content Descriptions
                if (content_type == DW_LNCT_path) {
                    path = xdb::attr(0, form, cur.data(), cu).as_string();  // TODO: shouldn't use fake attr
                    cur.skip_form(form);
                } else {
                    cur.skip_form(form);
                    // skip, we only care about path for now
                }
            }

            if (path.empty()) {
                xdb::error::send("Directory is empty");
            }
            if (path.is_absolute()) {
                dirs.emplace_back(path);
            } else {
                // relative path
                dirs.push_back(dirs[0] / path);
            }
        }
    }

    std::vector<xdb::line_table::file> files;
    {
        auto file_name_entry_format_count = cur.get_u8();
        std::vector<std::pair<DW_LNCT, DW_FORM>> file_format;
        for (auto i = 0; i < file_name_entry_format_count; ++i) {
            auto content_type = static_cast<DW_LNCT>(cur.get_uleb128());
            auto form = static_cast<DW_FORM>(cur.get_uleb128());
            file_format.emplace_back(content_type, form);
        }

        // file_names
        //
        // A sequence of file names and optional related information. Each entry is
        // encoded as described by the file_name_entry_format field.
        //
        // Entries in this sequence describe source files that contribute to the line
        // number information for this compilation or is used in other contexts, such as
        // in a declaration coordinate or a macro file inclusion.
        //
        // The first entry in the sequence is the primary source file whose file name
        // exactly matches that given in the DW_AT_name attribute in the compilation
        // unit debugging information entry.
        //
        // The line number program references file names in this sequence beginning
        // with 0, and uses those numbers instead of file names in the line number
        // program that follows.
        //
        // Prior to DWARF Version 5, the current compilation file name was not represented in
        // the file_names field. In DWARF Version 5, the current compilation file name is
        // explicitly present and has index 0. This is needed to support the common practice of
        // stripping all but the line number sections (.debug_line and .debug_line_str)
        // from an executable.
        auto files_count = cur.get_uleb128();
        for (size_t i = 0; i < files_count; ++i) {
            xdb::line_table::file file;

            for (auto [content_type, form] : file_format) {
                switch (content_type) {
                    case DW_LNCT_path: {
                        file.path = xdb::attr(0, form, cur.data(), cu).as_string();  // TODO: shouldn't use fake attr
                        cur.skip_form(form);
                        break;
                    }
                    case DW_LNCT_directory_index: {
                        file.directory_index = xdb::attr(0, form, cur.data(), cu).as_int();
                        cur.skip_form(form);
                        break;
                    }
                    case DW_LNCT_timestamp: {
                        // TODO: may not parse DW_FORM_block
                        file.timestamp = xdb::attr(0, form, cur.data(), cu).as_int();
                        cur.skip_form(form);
                        break;
                    }
                    case DW_LNCT_size: {
                        file.size = xdb::attr(0, form, cur.data(), cu).as_int();
                        cur.skip_form(form);
                        break;
                    }
                    default: {
                        cur.skip_form(form);
                        break;
                    }
                }
            }

            if (file.path.is_relative()) {
                file.path = dirs[file.directory_index] / file.path;
            }
            files.push_back(std::move(file));
        }
    }

    auto data = std::span<const std::byte>(cur.data(), end);
    return std::make_unique<xdb::line_table>(data, cu, default_is_stmt, line_base, line_range, opcode_base,
                                             std::move(dirs), std::move(files));
}

}  // namespace

namespace xdb {

compile_unit::compile_unit(dwarf& parent_dwarf, std::span<const std::byte> span, std::size_t abbrev_offset)
    : parent(&parent_dwarf), span_(span), abbrev_offset_(abbrev_offset) {
    line_table_ = parse_line_table(*this);
}

auto compile_unit::abbrev_table() const -> const std::unordered_map<std::uint64_t, abbrev>& {
    return parent->get_abbrev_table(abbrev_offset_);
}

auto compile_unit::root() const -> die {
    constexpr auto cu_header_size = 12;  // For 32-bit DWARF 5, see parse_compile_unit()
    cursor cur({span_.begin() + cu_header_size, span_.end()});
    return detail::parse_die(*this, cur);
}

auto compile_unit::addr_base() const -> std::uint32_t {
    if (!addr_base_) addr_base_ = root()[DW_AT_addr_base].as_section_offset();
    return *addr_base_;
}

auto compile_unit::str_offsets_base() const -> std::uint32_t {
    if (!str_offsets_base_) str_offsets_base_ = root()[DW_AT_str_offsets_base].as_section_offset();
    return *str_offsets_base_;
}

}  // namespace xdb
