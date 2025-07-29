#include <fmt/base.h>
#include <fmt/format.h>
#include <fmt/ranges.h>

#include <iostream>
#include <libxdb/parse.hpp>
#include <libxdb/register_info.hpp>
#include <libxdb/registers.hpp>
#include <type_traits>

#include "handlers.hpp"

namespace {

xdb::registers::value parse_register_value(const xdb::register_info &info, const std::string &value_str) {
    try {
        switch (info.format) {
            case xdb::register_format::uint:
                switch (info.size) {
                    case sizeof(std::uint8_t):
                        return xdb::to_integral<std::uint8_t>(value_str).value();
                    case sizeof(std::uint16_t):
                        return xdb::to_integral<std::uint16_t>(value_str).value();
                    case sizeof(std::uint32_t):
                        return xdb::to_integral<std::uint32_t>(value_str).value();
                    case sizeof(std::uint64_t):
                        return xdb::to_integral<std::uint64_t>(value_str).value();
                    default:
                        break;
                }
                break;
            case xdb::register_format::double_float:
                return xdb::to_float<double>(value_str).value();
            case xdb::register_format::long_double:
                return xdb::to_float<long double>(value_str).value();
            case xdb::register_format::vector:
                constexpr std::size_t vector_8_size = 8;
                if (info.size == vector_8_size) {
                    return xdb::parse_vector<vector_8_size>(value_str);
                }
        }
    } catch (...) {
        xdb::error::send("Invalid format");
    }
    xdb::error::send("Invalid format");
}

void handle_register_read(xdb::process &process, std::span<const std::string> args) {
    auto format = [](auto value) {
        if constexpr (std::is_floating_point_v<decltype(value)>) {
            return fmt::format("{}", value);
        } else if constexpr (std::is_integral_v<decltype(value)>) {
            return fmt::format("{:#0{}x}", value, (sizeof(value) * 2) + 2);
        } else {  // byte64 & byte128 -> std::array<std::byte, _>
            return fmt::format("[{:#04x}]", fmt::join(value, ", "));
        }
    };

    if (args.size() == 2 || (args.size() == 3 && args[2] == "all")) {
        auto all = args.size() == 3;
        for (const auto &info : xdb::g_register_infos) {
            auto is_gpr = info.type == xdb::register_type::gpr && info.id != xdb::register_id::orig_rax;
            auto should_print = all || is_gpr;
            if (should_print) {
                auto value = process.get_registers().read(info);
                fmt::println("{}:\t{}", info.name, std::visit(format, value));
            }
        }
    } else if (args.size() == 3) {
        try {
            auto info = xdb::register_info_by_name(args[2]);
            auto value = process.get_registers().read(info);
            fmt::println("{}:\t{}", info.name, std::visit(format, value));
        } catch (const xdb::error &e) {
            std::cerr << "No such register\n";
        }
    } else {
        xdb_handlers::print_help_init({"help", "register"});
    }
}

void handle_register_write(xdb::process &process, std::span<const std::string> args) {
    if (args.size() != 4) {
        xdb_handlers::print_help_init({"help", "register"});
        return;
    }
    try {
        auto info = xdb::register_info_by_name(args[2]);
        auto value = parse_register_value(info, args[3]);
        process.get_registers().write(info, value);
    } catch (const xdb::error &e) {
        std::cerr << "Error writing to register: " << e.what() << '\n';
    }
}

}  // namespace

namespace xdb_handlers {

void handle_register_command(xdb::process &process, std::span<const std::string> args) {
    if (args.size() < 2) {
        print_help_init({"help", "register"});
        return;
    }

    if (args[1] == "read") {
        handle_register_read(process, args);
    } else if (args[1] == "write") {
        handle_register_write(process, args);
    } else {
        print_help_init({"help", "register"});
    }
}

}  // namespace xdb_handlers
