#include <fmt/base.h>
#include <fmt/format.h>

#include <libxdb/parse.hpp>
#include <libxdb/types.hpp>

#include "handlers.hpp"

namespace {

void print_all_breakpoints(xdb::process &process) {
    if (process.breakpoint_sites().empty()) {
        fmt::println("No breakpoints set.");
        return;
    }
    fmt::println("Breakpoints:");
    process.breakpoint_sites().for_each([](const auto &breakpoint_site) {
        if (breakpoint_site.is_internal()) {
            return;  // Skip internal breakpoints
        }
        fmt::println("{}: address = {:#x}, {}, {}", breakpoint_site.id(), breakpoint_site.address().addr(),
                     breakpoint_site.is_hardware() ? "hardware" : "software",
                     breakpoint_site.is_enabled() ? "enabled" : "disabled");
    });
}

}  // namespace

namespace xdb_handlers {

void handle_breakpoint_command(xdb::process &process, std::span<const std::string> args) {
    auto phelp = []() { print_help_init({"help", "breakpoint"}); };

    if (args.size() < 2) {
        phelp();
        return;
    }

    auto cmd = args[1];
    if (cmd == "list") {
        print_all_breakpoints(process);
        return;
    }

    if (cmd == "set") {
        if (args.size() < 3) {
            phelp();
            return;
        }
        constexpr int hex_base = 16;
        auto address = xdb::to_integral<std::uint64_t>(args[2], hex_base);
        if (!address) {
            fmt::println("Address is expected in 0xhex format");
            return;
        }
        bool hardware = false;
        if (args.size() > 3) {
            if (args[3] == "--hardware" || args[3] == "-h") {
                hardware = true;
            } else {
                xdb::error::send("Invalid argument");
            }
        }
        process.create_breakpoint_site(xdb::virt_addr{*address}, hardware).enable();
        return;
    }

    if (args.size() < 3) {
        phelp();
        return;
    }
    auto breakpoint_id = xdb::to_integral<xdb::breakpoint_site::id_type>(args[2]);
    if (!breakpoint_id) {
        fmt::println("Command expects valid breakpoint ID");
        return;
    }

    if (cmd == "enable") {
        process.breakpoint_sites().get_by_id(*breakpoint_id).enable();
    } else if (cmd == "disable") {
        process.breakpoint_sites().get_by_id(*breakpoint_id).disable();
    } else if (cmd == "delete") {
        process.breakpoint_sites().remove_by_id(*breakpoint_id);
    } else {
        fmt::println("Unknown breakpoint command: {}", cmd);
        phelp();
    }
}

}  // namespace xdb_handlers
