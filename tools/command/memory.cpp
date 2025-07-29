#include <fmt/base.h>
#include <fmt/format.h>

#include <iostream>
#include <libxdb/parse.hpp>
#include <libxdb/types.hpp>
#include <span>

#include "handlers.hpp"

namespace {

void handle_memory_read(xdb::process &process, std::span<const std::string> args) {
    constexpr std::size_t default_read_bytes = 32;
    constexpr std::size_t bytes_per_line = 16;

    if (args.size() < 3) {
        xdb_handlers::print_help_init({"help", "memory"});
        return;
    }

    constexpr int hex_base = 16;
    auto address = xdb::to_integral<std::uint64_t>(args[2], hex_base);
    if (!address) {
        std::cerr << "Invalid address format. Use 0x prefix for hex addresses.\n";
        return;
    }

    std::size_t size = default_read_bytes;  // Default size
    if (args.size() >= 4) {
        auto size_opt = xdb::to_integral<std::size_t>(args[3]);
        if (!size_opt) {
            std::cerr << "Invalid size value.\n";
            return;
        }
        size = *size_opt;
    }

    try {
        auto data = process.read_memory(xdb::virt_addr{*address}, size);

        // Print in hex dump format (16 bytes per line, no ASCII)
        for (std::size_t i = 0; i < data.size(); i += bytes_per_line) {
            fmt::print("{:#016x}: ", *address + i);

            // Print hex bytes (max 16 per line)
            for (std::size_t j = 0; j < bytes_per_line && i + j < data.size(); ++j) {
                fmt::print("{:02x} ", static_cast<std::uint8_t>(data[i + j]));
            }

            fmt::println("");
        }
    } catch (const xdb::error &e) {
        std::cerr << "Error reading memory: " << e.what() << '\n';
    }
}

void handle_memory_write(xdb::process &process, std::span<const std::string> args) {
    if (args.size() < 4) {
        xdb_handlers::print_help_init({"help", "memory"});
        return;
    }

    constexpr int hex_base = 16;
    auto address = xdb::to_integral<std::uint64_t>(args[2], hex_base);
    if (!address) {
        std::cerr << "Invalid address format. Use 0x prefix for hex addresses.\n";
        return;
    }

    try {
        auto bytes = xdb::parse_vector(args[3]);
        if (bytes.empty()) {
            std::cerr << "No data to write.\n";
            return;
        }

        process.write_memory(xdb::virt_addr{*address}, std::span<const std::byte>(bytes));
        fmt::println("Successfully wrote {} bytes to {:#x}", bytes.size(), *address);

        // Show what was written
        fmt::print("Data written: [");
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            if (i > 0) {
                fmt::print(",");
            }
            fmt::print("{:#04x}", static_cast<std::uint8_t>(bytes[i]));
        }
        fmt::println("]");

    } catch (const xdb::error &e) {
        std::cerr << "Error writing memory: " << e.what() << '\n';
    }
}

}  // namespace

namespace xdb_handlers {

void handle_memory_command(xdb::process &process, std::span<const std::string> args) {
    if (args.size() < 2) {
        print_help_init({"help", "memory"});
        return;
    }

    if (args[1] == "read") {
        handle_memory_read(process, args);
    } else if (args[1] == "write") {
        handle_memory_write(process, args);
    } else {
        print_help_init({"help", "memory"});
    }
}

}  // namespace xdb_handlers
