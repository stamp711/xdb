#include <filesystem>
#include <iomanip>
#include <iostream>
#include <libxdb/dwarf.hpp>
#include <libxdb/elf.hpp>
#include <magic_enum/magic_enum.hpp>
#include <sstream>
#include <string>

class dwarf_dumper {
   private:
    const xdb::elf& elf_;
    const xdb::dwarf& dwarf_;
    std::size_t current_cu_offset_ = 0;

    static std::string get_tag_name(dw_tag_t tag) {
        auto name = magic_enum::enum_name(tag);
        if (name.empty()) {
            std::stringstream ss;
            ss << "DW_TAG_unknown_" << std::hex << static_cast<std::uint64_t>(tag);
            return ss.str();
        }
        return std::string(name);
    }

    static std::string get_attr_name(dw_attr_type_t attr) {
        auto name = magic_enum::enum_name(attr);
        if (name.empty()) {
            std::stringstream ss;
            ss << "DW_AT_unknown_" << std::hex << static_cast<std::uint64_t>(attr);
            return ss.str();
        }
        return std::string(name);
    }

    static std::string get_form_name(dw_form_t form) {
        auto name = magic_enum::enum_name(form);
        if (name.empty()) {
            std::stringstream ss;
            ss << "DW_FORM_unknown_" << std::hex << static_cast<std::uint64_t>(form);
            return ss.str();
        }
        return std::string(name);
    }

    std::string decode_strp_value(std::uint32_t offset) {
        auto debug_str = elf_.get_section_contents(".debug_str");
        if (offset >= debug_str.size()) {
            return "<invalid string offset>";
        }
        std::span<const std::byte> str_span(debug_str.data() + offset, debug_str.size() - offset);
        xdb::cursor str_cur(str_span);
        return std::string(str_cur.get_string());
    }

    std::string decode_line_strp_value(std::uint32_t offset) {
        auto debug_line_str = elf_.get_section_contents(".debug_line_str");
        if (!debug_line_str.empty() && offset < debug_line_str.size()) {
            std::span<const std::byte> str_span(debug_line_str.data() + offset, debug_line_str.size() - offset);
            xdb::cursor str_cur(str_span);
            return std::string(str_cur.get_string());
        }
        // Fallback to debug_str
        return decode_strp_value(offset);
    }

    static std::string decode_attribute_value(const xdb::attr& attr, const xdb::die& die) {
        std::stringstream ss;

        switch (attr.form()) {
            case dw_form_t::DW_FORM_addr: {
                auto addr_val = attr.get<dw_form_t::DW_FORM_addr>();
                ss << "0x" << std::hex << std::setfill('0') << std::setw(8) << addr_val.addr();
                return ss.str();
            }

            case dw_form_t::DW_FORM_flag_present: {
                return "yes(1)";
            }

            case dw_form_t::DW_FORM_strp:
            case dw_form_t::DW_FORM_line_strp:
            case dw_form_t::DW_FORM_string: {
                return "<string value>";
            }

            default: {
                // For high_pc that's not an address, show special formatting
                if (attr.type() == dw_attr_type_t::DW_AT_high_pc && attr.form() != dw_form_t::DW_FORM_addr) {
                    ss << "<offset-from-lowpc> <value>";
                    if (die.contains(dw_attr_type_t::DW_AT_low_pc)) {
                        auto low_pc_attr = die[dw_attr_type_t::DW_AT_low_pc];
                        if (low_pc_attr.form() == dw_form_t::DW_FORM_addr) {
                            ss << " <highpc: calculated>";
                        }
                    }
                    return ss.str();
                }

                // Default case - show form type
                ss << "<" << get_form_name(attr.form()) << " value>";
                return ss.str();
            }
        }
    }

    static void print_die_attributes(const xdb::die& die, int depth, std::size_t /* die_offset */) {
        const auto& abbrev = die.abbreviation();

        for (const auto& attr_spec : abbrev.attrs) {
            if (die.contains(attr_spec.type)) {
                auto attr = die[attr_spec.type];

                // Print proper indentation and spacing to match dwarfdump format
                for (int i = 0; i <= depth; ++i) {
                    std::cout << " ";
                }

                std::cout << "                  " << get_attr_name(attr_spec.type);

                // Calculate padding to align values nicely
                std::string attr_name = get_attr_name(attr_spec.type);
                int padding = std::max(1, 30 - static_cast<int>(attr_name.length()));
                for (int i = 0; i < padding; ++i) {
                    std::cout << " ";
                }

                std::string value = decode_attribute_value(attr, die);
                std::cout << value;

                std::cout << '\n';
            }
        }
    }

    void print_die(const xdb::die& die, int depth) {
        if (die.is_null()) {
            return;
        }

        const auto& abbrev = die.abbreviation();

        // Print the DIE header with depth and real DWARF offset
        std::cout << "<" << std::setw(2) << std::setfill(' ') << depth << "><0x" << std::hex << std::setfill('0')
                  << std::setw(8) << die.offset_in_debug_info() << ">  ";

        // Add proper indentation based on depth
        for (int i = 1; i < depth; ++i) {
            std::cout << "  ";
        }

        std::cout << get_tag_name(abbrev.tag) << '\n';

        // Print attributes
        print_die_attributes(die, depth, 0);

        // Print children with real offsets
        if (abbrev.has_children) {
            // Add LOCAL_SYMBOLS marker before printing child DIEs at root level
            if (depth == 0) {
                std::cout << '\n' << "LOCAL_SYMBOLS:\n";
            }

            for (const auto& child : die.children()) {
                print_die(child, depth + 1);
            }
        }
    }

   public:
    dwarf_dumper(const xdb::elf& elf, const xdb::dwarf& dwarf) : elf_(elf), dwarf_(dwarf) {}

    void dump_debug_info() {
        std::cout << ".debug_info\n\n";

        const auto& compile_units = dwarf_.compile_units();

        for (std::size_t cu_idx = 0; cu_idx < compile_units.size(); ++cu_idx) {
            const auto& cu = compile_units[cu_idx];

            // Print compile unit header
            std::cout << "COMPILE_UNIT<header overall offset = 0x" << std::hex << std::setfill('0') << std::setw(8)
                      << current_cu_offset_ << ">:\n";

            auto root_die = cu->root();

            // Print the root DIE with real offset
            print_die(root_die, 0);

            // Update offset for next CU (this is a rough estimate)
            current_cu_offset_ += cu->span().size();

            if (cu_idx < compile_units.size() - 1) {
                std::cout << '\n';
            }
        }
    }

    void dump_debug_str() {
        auto debug_str = elf_.get_section_contents(".debug_str");
        if (debug_str.empty()) {
            return;
        }

        std::cout << "\n.debug_str\n";

        xdb::cursor cur(debug_str);
        std::size_t offset = 0;

        while (!cur.finished() && offset < debug_str.size()) {
            auto str = cur.get_string();
            if (!str.empty()) {
                std::cout << "name at offset 0x" << std::hex << std::setfill('0') << std::setw(8) << offset
                          << ", length " << std::dec << std::setw(4) << str.length() << " is '" << str << "'" << '\n';
            }
            offset += str.length() + 1;  // +1 for null terminator

            // Safety check to prevent infinite loops
            if (offset >= debug_str.size()) {
                break;
            }
        }
    }

    void dump_debug_line() {
        auto debug_line = elf_.get_section_contents(".debug_line");
        if (debug_line.empty()) {
            return;
        }

        std::cout << "\n.debug_line: line number info for a single cu\n";
        std::cout << "Source lines (from CU-DIE at .debug_info offset 0x" << std::hex << std::setfill('0')
                  << std::setw(8) << 0 << "):\n";
        std::cout << '\n';
        std::cout << "            NS new statement, BB new basic block, ET end of text sequence\n";
        std::cout << "            PE prologue end, EB epilogue begin\n";
        std::cout << "            IS=val ISA number, DI=val discriminator value\n";
        std::cout << "<pc>        [lno,col] NS BB ET PE EB IS= DI= uri: \"filepath\"\n";

        // This is a simplified placeholder - full line table parsing would be complex
        std::cout << "<line table parsing not fully implemented>\n";
    }

    void dump_all() {
        dump_debug_info();
        dump_debug_str();
        dump_debug_line();
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <binary_file_path>\n";
        return 1;
    }

    std::filesystem::path binary_path = argv[1];

    if (!std::filesystem::exists(binary_path)) {
        std::cerr << "Error: File '" << binary_path << "' does not exist.\n";
        return 1;
    }

    xdb::elf elf_file(binary_path);
    xdb::dwarf dwarf_info(elf_file);

    dwarf_dumper dumper(elf_file, dwarf_info);
    dumper.dump_all();

    return 0;
}
