#include <fmt/base.h>
#include <fmt/format.h>

#include <exception>
#include <libxdb/parse.hpp>
#include <libxdb/types.hpp>

#include "handlers.hpp"

namespace {

void print_all_watchpoints(xdb::process &process) {
    if (process.watchpoints().empty()) {
        fmt::println("No watchpoints set.");
        return;
    }
    fmt::println("Watchpoints:");
    process.watchpoints().for_each([](const auto &watchpoint) {
        const char *mode_str = "";
        switch (watchpoint.mode()) {
            case xdb::stoppoint_mode::write:
                mode_str = "write";
                break;
            case xdb::stoppoint_mode::read_write:
                mode_str = "read_write";
                break;
            case xdb::stoppoint_mode::execute:
                mode_str = "execute";
                break;
        }
        fmt::println("{}: address = {:#x}, mode = {}, size = {}, {}", watchpoint.id(), watchpoint.address().addr(),
                     mode_str, watchpoint.size(), watchpoint.is_enabled() ? "enabled" : "disabled");
    });
}

void handle_watchpoint_set(xdb::process &process, std::span<const std::string> args) {
    auto phelp = []() { xdb_handlers::print_help_init({"help", "watchpoint"}); };

    if (args.size() < 5) {
        phelp();
        return;
    }
    constexpr int hex_base = 16;
    auto address = xdb::to_integral<std::uint64_t>(args[2], hex_base);
    if (!address) {
        fmt::println("Address is expected in 0xhex format");
        return;
    }

    // Parse mode
    xdb::stoppoint_mode mode = xdb::stoppoint_mode::execute;
    if (args[3] == "write") {
        mode = xdb::stoppoint_mode::write;
    } else if (args[3] == "read_write" || args[3] == "rw") {
        mode = xdb::stoppoint_mode::read_write;
    } else if (args[3] == "execute") {
        mode = xdb::stoppoint_mode::execute;
    } else {
        fmt::println("Invalid mode. Use 'write' or 'read_write'");
        return;
    }

    // Parse size
    auto size = xdb::to_integral<std::size_t>(args[4]);
    if (!size || (*size != 1 && *size != 2 && *size != 4 && *size != 8)) {
        fmt::println("Invalid size. Use 1, 2, 4, or 8");
        return;
    }

    try {
        process.create_watchpoint(xdb::virt_addr{*address}, mode, *size).enable();
        fmt::println("Watchpoint set at {:#x}", *address);
    } catch (const std::exception &e) {
        fmt::println("Error setting watchpoint: {}", e.what());
    }
}

}  // namespace

namespace xdb_handlers {

void handle_watchpoint_command(xdb::process &process, std::span<const std::string> args) {
    auto phelp = []() { print_help_init({"help", "watchpoint"}); };

    if (args.size() < 2) {
        phelp();
        return;
    }

    auto cmd = args[1];
    if (cmd == "list") {
        print_all_watchpoints(process);
        return;
    }

    if (cmd == "set") {
        handle_watchpoint_set(process, args);
        return;
    }

    if (args.size() < 3) {
        phelp();
        return;
    }
    auto watchpoint_id = xdb::to_integral<xdb::watchpoint::id_type>(args[2]);
    if (!watchpoint_id) {
        fmt::println("Command expects valid watchpoint ID");
        return;
    }

    if (cmd == "enable") {
        try {
            process.watchpoints().get_by_id(*watchpoint_id).enable();
            fmt::println("Watchpoint {} enabled", *watchpoint_id);
        } catch (const std::exception &e) {
            fmt::println("Error: {}", e.what());
        }
    } else if (cmd == "disable") {
        try {
            process.watchpoints().get_by_id(*watchpoint_id).disable();
            fmt::println("Watchpoint {} disabled", *watchpoint_id);
        } catch (const std::exception &e) {
            fmt::println("Error: {}", e.what());
        }
    } else if (cmd == "delete") {
        try {
            process.watchpoints().remove_by_id(*watchpoint_id);
            fmt::println("Watchpoint {} deleted", *watchpoint_id);
        } catch (const std::exception &e) {
            fmt::println("Error: {}", e.what());
        }
    } else {
        fmt::println("Unknown watchpoint command: {}", cmd);
        phelp();
    }
}

}  // namespace xdb_handlers
