#include <fmt/base.h>
#include <fmt/format.h>

#include <libxdb/parse.hpp>
#include <libxdb/process.hpp>
#include <libxdb/syscalls.hpp>
#include <libxdb/types.hpp>
#include <sstream>
#include <unordered_set>

#include "handlers.hpp"

namespace {

std::vector<std::string> split_comma_separated(const std::string& str) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;

    while (std::getline(ss, item, ',')) {
        // Trim whitespace
        item.erase(0, item.find_first_not_of(" \t"));
        item.erase(item.find_last_not_of(" \t") + 1);
        if (!item.empty()) {
            result.push_back(item);
        }
    }

    return result;
}

std::optional<std::uint64_t> parse_syscall_identifier(const std::string& identifier) {
    // Try to parse as number first
    auto as_number = xdb::to_integral<std::uint64_t>(identifier);
    if (as_number) {
        return as_number;
    }

    // Try to parse as syscall name
    std::uint64_t syscall_id = xdb::syscall_name_to_id(identifier);
    if (syscall_id != static_cast<std::uint64_t>(-1)) {
        return syscall_id;
    }

    return std::nullopt;
}

}  // namespace

namespace xdb_handlers {

void handle_catchpoint_command(xdb::process& process, std::span<const std::string> args) {
    auto phelp = []() { print_help_init({"help", "catchpoint"}); };

    if (args.size() < 2) {
        phelp();
        return;
    }

    auto cmd = args[1];

    // Handle "catch syscall" or "catch sys" commands
    if (cmd == "syscall" || cmd == "sys") {
        if (args.size() < 3) {
            // Both "catch syscall" and "catch sys" with no arguments means catch all syscalls
            auto policy = xdb::syscall_catch_policy::catch_all();
            process.set_syscall_catch_policy(std::move(policy));
            fmt::println("Now catching all syscalls.");
            return;
        }

        const auto& syscall_arg = args[2];

        // Handle "catch sys none"
        if (syscall_arg == "none") {
            auto policy = xdb::syscall_catch_policy::catch_none();
            process.set_syscall_catch_policy(std::move(policy));
            fmt::println("No longer catching any syscalls.");
            return;
        }

        // Parse comma-separated syscall identifiers
        auto syscall_identifiers = split_comma_separated(syscall_arg);
        std::unordered_set<std::uint64_t> syscall_ids;

        for (const auto& identifier : syscall_identifiers) {
            auto syscall_id = parse_syscall_identifier(identifier);
            if (!syscall_id) {
                fmt::println("Error: Unknown syscall identifier '{}'", identifier);
                return;
            }
            syscall_ids.insert(*syscall_id);
        }

        if (syscall_ids.empty()) {
            fmt::println("Error: No valid syscall identifiers provided");
            return;
        }

        // Convert unordered_set to vector for syscall_catch_policy::catch_some
        std::vector<std::uint64_t> syscall_vector(syscall_ids.begin(), syscall_ids.end());
        auto policy = xdb::syscall_catch_policy::catch_some(syscall_vector);
        process.set_syscall_catch_policy(std::move(policy));

        fmt::println("Now catching {} syscall(s):", syscall_ids.size());
        for (auto id : syscall_ids) {
            auto name = xdb::syscall_id_to_name(id);
            fmt::println("  {} ({})", name, id);
        }

        return;
    }

    fmt::println("Unknown catchpoint command: {}", cmd);
    phelp();
}

}  // namespace xdb_handlers
