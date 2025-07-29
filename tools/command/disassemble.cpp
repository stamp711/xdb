#include <fmt/base.h>
#include <fmt/format.h>

#include <libxdb/disassembler.hpp>
#include <libxdb/parse.hpp>
#include <libxdb/types.hpp>

#include "handlers.hpp"

namespace xdb_handlers {

void print_disassembly(xdb::process &process, xdb::virt_addr address, std::size_t n_instructions) {
    xdb::disassembler dis(process);
    auto instructions = dis.disassemble(n_instructions, address);
    for (const auto &instruction : instructions) {
        fmt::println("{:08x}: {}", instruction.address.addr(), instruction.text);
    }
}

void handle_disassemble_command(xdb::process &process, std::span<const std::string> args) {
    auto address = process.get_pc();
    constexpr std::size_t default_instruction_count = 5;
    std::size_t n_instructions = default_instruction_count;

    // Parse command line arguments for -c and -a flags
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "-c" && i + 1 < args.size()) {
            auto count = xdb::to_integral<std::size_t>(args[i + 1]);
            if (!count) {
                fmt::println("Invalid instruction count format.");
                return;
            }
            n_instructions = *count;
            ++i;  // Skip the argument we just consumed
        } else if (args[i] == "-a" && i + 1 < args.size()) {
            constexpr int hex_base = 16;
            auto addr = xdb::to_integral<std::uint64_t>(args[i + 1], hex_base);
            if (!addr) {
                fmt::println("Invalid address format. Address is expected in 0xhex format.");
                return;
            }
            address = xdb::virt_addr{*addr};
            ++i;  // Skip the argument we just consumed
        }
    }

    print_disassembly(process, address, n_instructions);
}

}  // namespace xdb_handlers
