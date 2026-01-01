#include <elf.h>
#include <fmt/base.h>
#include <fmt/format.h>

#include <cstdint>
#include <libxdb/breakpoint_site.hpp>
#include <libxdb/parse.hpp>
#include <libxdb/types.hpp>
#include <ranges>
#include <string_view>

#include "handlers.hpp"

namespace {

void print_all_breakpoints(xdb::target& target) {
    if (target.breakpoints().empty()) {
        fmt::println("No breakpoints set.");
        return;
    }

    fmt::print("Current breakpoints:\n");
    target.breakpoints().for_each([](const auto& bp) -> void {
        if (bp.is_internal()) return;
        fmt::print("{}: ", bp.id());
        if (const auto* func_bp = dynamic_cast<const xdb::function_breakpoint*>(&bp)) {
            fmt::print("function = {}", func_bp->function_name());
        } else if (const auto* line_bp = dynamic_cast<const xdb::line_breakpoint*>(&bp)) {
            fmt::print("file = {}, line = {}", line_bp->file().string(), line_bp->line());
        } else if (const auto* addr_bp = dynamic_cast<const xdb::address_breakpoint*>(&bp)) {
            fmt::print("address = {:#x}", addr_bp->address().addr());
        }
        fmt::print(", {}, {}:\n", bp.is_hardware() ? "hardware" : "software", bp.is_enabled() ? "enabled" : "disabled");
        bp.breakpoint_sites().for_each([&](auto& site) -> void {
            fmt::print("    .{}: address = {:#x}, {}\n", site.id(), site.address().addr(),
                       site.is_enabled() ? "enabled" : "disabled");
        });
    });
}

void handle_breakpoint_set(xdb::target& target, std::span<const std::string> args) {
    bool hardware = false;
    if (args.size() > 3) {
        if (args[3] == "--hardware" || args[3] == "-h") {
            hardware = true;
        } else {
            fmt::println(stderr, "Invalid argument");
            return;
        }
    }

    const auto& spec = args[2];
    if (spec.starts_with("0x")) {
        // breakpoint set 0x<address>
        auto address = xdb::to_integral<uint64_t>(spec, /*base=*/16);
        if (!address) {
            fmt::println(stderr, "Expected a valid hexadecimal address prefixed with '0x'");
            return;
        }

        target.create_address_breakpoint(xdb::virt_addr{*address}, hardware).enable();

    } else if (spec.find(':') != std::string::npos) {
        // breakpoint set <file>:<line>
        std::vector<std::string_view> out =
            spec | std::views::split(':') |
            std::views::transform([](auto&& part) -> std::string_view { return {part.begin(), part.end()}; }) |
            std::ranges::to<std::vector>();
        auto file = out[0];
        auto line = xdb::to_integral<uint64_t>(out[1]);
        if (!line) {
            fmt::println(stderr, "Expected a valid file:line format, line should be integer");
            return;
        }

        target.create_line_breakpoint(file, *line, hardware).enable();

    } else {
        // breakpoint set <function name>
        target.create_function_breakpoint(spec, hardware).enable();
    }
}

void handle_breakpoint_toggle(xdb::target& target, std::span<const std::string> args) {
    const auto& cmd = args[1];
    const auto& id_pos_spec = args[2];

    auto dot_pos = id_pos_spec.find('.');
    auto id = xdb::to_integral<xdb::breakpoint::id_type>(id_pos_spec.substr(0, dot_pos));
    if (!id) {
        fmt::println(stderr, "Expected a valid breakpoint id");
        return;
    }
    auto& bp = target.breakpoints().get_by_id(*id);

    std::optional<xdb::breakpoint_site::id_type> site_id;
    if (dot_pos != std::string::npos) {
        site_id = xdb::to_integral<xdb::breakpoint_site::id_type>(id_pos_spec.substr(dot_pos + 1));
        if (!site_id) {
            fmt::println(stderr, "Expected a valid site id");
            return;
        }
    }

    if (cmd == "enable") {
        if (site_id) {
            bp.breakpoint_sites().get_by_id(*site_id).enable();
        } else {
            bp.enable();
        }
    } else if (cmd == "disable") {
        if (site_id) {
            bp.breakpoint_sites().get_by_id(*site_id).disable();
        } else {
            bp.disable();
        }
    } else if (cmd == "delete") {
        // We only support delete whole logic breakpoint for now
        if (site_id) {
            fmt::print(stderr, "Cannot delete site breakpoint");
        } else {
            bp.breakpoint_sites().for_each([&target](auto& site) -> void {
                target.get_process().breakpoint_sites().remove_by_address(site.address());
            });
            target.breakpoints().remove_by_id(bp.id());
        }
    } else {
        fmt::println(stderr, "Unknown breakpoint command");
    }
}

}  // namespace

namespace xdb_handlers {

void handle_breakpoint_command(xdb::target& target, std::span<const std::string> args) {
    auto phelp = []() -> void { print_help_init({"help", "breakpoint"}); };

    if (args.size() < 2) {
        phelp();
        return;
    }

    const auto& cmd = args[1];
    if (cmd == "list") {
        print_all_breakpoints(target);
        return;
    }

    if (cmd == "set") {
        if (args.size() < 3) {
            phelp();
            return;
        }
        handle_breakpoint_set(target, args);
        return;
    }

    if (args.size() < 3) {
        phelp();
        return;
    }
    handle_breakpoint_toggle(target, args);
}

}  // namespace xdb_handlers
