#include <elf.h>
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

std::optional<xdb::virt_addr> resolve_address_or_symbol(const xdb::target &target, const std::string &addr_or_symbol) {
    // Try to parse as hex address first
    constexpr int hex_base = 16;
    auto address = xdb::to_integral<std::uint64_t>(addr_or_symbol, hex_base);
    if (address) {
        return xdb::virt_addr{*address};
    }

    // Not a hex address, try to resolve as symbol
    auto symbols = target.get_elf().get_symbols_by_name(addr_or_symbol);
    if (symbols.empty()) {
        fmt::println("Symbol '{}' not found", addr_or_symbol);
        return std::nullopt;
    }

    // Filter for function symbols
    std::vector<const Elf64_Sym *> function_symbols;
    for (const auto *symbol : symbols) {
        if (ELF64_ST_TYPE(symbol->st_info) == STT_FUNC) {
            function_symbols.push_back(symbol);
        }
    }

    if (function_symbols.empty()) {
        fmt::println("Symbol '{}' found but is not a function", addr_or_symbol);
        return std::nullopt;
    }

    if (function_symbols.size() > 1) {
        fmt::println("Multiple function symbols found for '{}', using the first one:", addr_or_symbol);
        for (const auto *symbol : function_symbols) {
            fmt::println("  {:#x}", symbol->st_value + target.get_elf().load_bias().addr());
        }
    }

    // Use the first function symbol found
    const auto *symbol = function_symbols[0];
    auto symbol_addr = xdb::virt_addr{symbol->st_value + target.get_elf().load_bias().addr()};
    fmt::println("Setting breakpoint at function '{}' (address {:#x})", addr_or_symbol, symbol_addr.addr());
    return symbol_addr;
}

}  // namespace

namespace xdb_handlers {

void handle_breakpoint_command(xdb::target &target, std::span<const std::string> args) {
    auto &process = target.get_process();
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

        auto address = resolve_address_or_symbol(target, args[2]);
        if (!address) {
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
        process.create_breakpoint_site(*address, hardware).enable();
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
