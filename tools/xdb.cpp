#include <editline/readline.h>
#include <fcntl.h>
#include <fmt/base.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <iostream>
#include <libxdb/breakpoint_site.hpp>
#include <libxdb/disassembler.hpp>
#include <libxdb/parse.hpp>
#include <libxdb/process.hpp>
#include <libxdb/register_info.hpp>
#include <libxdb/registers.hpp>
#include <libxdb/types.hpp>
#include <memory>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace {

std::unique_ptr<xdb::process> attach(std::span<const char *const> args) {
    if (args.size() < 2) {
        std::cerr << "Usage: xdb [-p PID] [program_path]\n";
        return nullptr;
    }

    if (args.size() == 3 && args[1] == std::string_view("-p")) {
        // Attaching to a process by PID
        pid_t pid = static_cast<pid_t>(std::stoi(args[2]));
        return xdb::process::attach(pid);
    }

    std::filesystem::path path(args[1]);
    return xdb::process::launch(path);
}

std::vector<std::string> split(std::string_view str, char delimiter) {
    std::vector<std::string> tokens;
    size_t start = 0;
    while (start < str.size()) {
        auto end = str.find(delimiter, start);
        if (end == std::string_view::npos) {
            end = str.size();  // If no more delimiters, take the rest of the
                               // string
        }
        if (end > start) {
            // Only add non-empty tokens
            tokens.emplace_back(str.substr(start, end - start));
        }
        start = end + 1;
    }
    return tokens;
}

void print_stop_reason(const xdb::process &process,
                       const xdb::stop_reason &reason) {
    std::string message;
    const char *sig = nullptr;
    switch (reason.state) {
        case xdb::process_state::running:
            message = "is running";
            break;
        case xdb::process_state::stopped:
            sig = sigabbrev_np(reason.info);
            message = fmt::format("stopped by signal {} at {:#x}", sig,
                                  process.get_pc().addr());
            break;
        case xdb::process_state::exited:
            message = fmt::format("exited with status {}", reason.info);
            break;
        case xdb::process_state::terminated:
            sig = sigabbrev_np(reason.info);
            message = fmt::format("terminated by signal {}", sig);
            break;
        default:
            message = "state is unknown";
    }
    fmt::println("Process {} {}", process.pid(), message);
}

void print_disassembly(xdb::process &process, xdb::virt_addr address,
                       std::size_t n_instructions) {
    xdb::disassembler dis(process);
    auto instructions = dis.disassemble(n_instructions, address);
    for (const auto &instruction : instructions) {
        fmt::println("{:08x}: {}", instruction.address.addr(),
                     instruction.text);
    }
}

void handle_stop(xdb::process &process, xdb::stop_reason reason) {
    print_stop_reason(process, reason);
    if (reason.state == xdb::process_state::stopped) {
        constexpr std::size_t print_instruction_count = 5;
        print_disassembly(process, process.get_pc(), print_instruction_count);
    }
}

void print_help(std::span<const std::string> args) {
    if (args.size() == 1) {
        std::cout << "Available commands:\n"
                  << "    help, h            - Show this help message\n"
                  << "    breakpoint, b      - Manage breakpoints\n"
                  << "    continue, c        - Resume the process\n"
                  << "    disassemble, disas - Disassemble instructions\n"
                  << "    memory, mem        - Memory operations\n"
                  << "    register, reg      - Register operations\n"
                  << "    stepi, si          - Single step an instruction\n"
                  << "    watchpoint, w      - Manage watchpoints\n";
    } else if (args[1] == "breakpoint" || args[1] == "b") {
        std::cout
            << "Manage breakpoints.\n"
            << "Usage:\n"
            << "    breakpoint list             - List all breakpoints\n"
            << "    breakpoint set <address>    - Set a breakpoint at the "
               "specified address\n"
            << "    breakpoint set <address> --hardware/-h"
            << "                                - Set a hardware breakpoint at "
               "the specified address\n"
            << "    breakpoint enable <id>      - Enable a breakpoint by ID\n"
            << "    breakpoint disable <id>     - Disable a breakpoint by ID\n"
            << "    breakpoint delete <id>      - Delete a breakpoint by ID\n";
    } else if (args[1] == "watchpoint" || args[1] == "w") {
        std::cout
            << "Manage watchpoints.\n"
            << "Usage:\n"
            << "    watchpoint list                       - List all "
               "watchpoints\n"
            << "    watchpoint set <address> <mode> <size> - Set a watchpoint\n"
            << "    watchpoint enable <id>                - Enable a "
               "watchpoint by ID\n"
            << "    watchpoint disable <id>               - Disable a "
               "watchpoint by ID\n"
            << "    watchpoint delete <id>                - Delete a "
               "watchpoint by ID\n"
            << "Modes:\n"
            << "    write                                 - Break on write "
               "access\n"
            << "    read_write, rw                        - Break on read or "
               "write access\n"
            << "    execute                               - Break on "
               "execution\n"
            << "Size:\n"
            << "    1, 2, 4, 8                           - Number of bytes to "
               "watch\n"
            << "Examples:\n"
            << "    watchpoint set 0x401000 write 4\n"
            << "    watchpoint set 0x7fff12345678 read_write 8\n";
    } else if (args[1] == "continue" || args[1] == "c") {
        std::cout << "Resume the process.\n";
    } else if (args[1] == "disassemble" || args[1] == "disas") {
        std::cout
            << "Disassemble instructions.\n"
            << "Usage:\n"
            << "    disassemble [-c <count>] [-a <address>]\n"
            << "    disas [-c <count>] [-a <address>]\n"
            << "Options:\n"
            << "    -c <count>     - Number of instructions to disassemble "
               "(default: 5)\n"
            << "    -a <address>   - Starting address (default: current PC)\n"
            << "Examples:\n"
            << "    disas\n"
            << "    disas -c 10\n"
            << "    disas -a 0x401000\n"
            << "    disas -c 8 -a 0x401000\n";
    } else if (args[1] == "memory" || args[1] == "mem") {
        std::cout
            << "Memory operations.\n"
            << "Usage:\n"
            << "    memory read <address> [size]     - Read memory at address "
               "(default size: 32 bytes)\n"
            << "    memory write <address> <data>    - Write data to memory\n"
            << "Examples:\n"
            << "    memory read 0x555555555156\n"
            << "    memory read 0x555555555156 16\n"
            << "    memory write 0x555555555156 [0xff,0xaa,0x11]\n";
    } else if (args[1] == "register" || args[1] == "reg") {
        std::cout << "Usage:\n"
                  << "    register read\n"
                  << "    register read <register>\n"
                  << "    register read all\n"
                  << "    register write <register> <value>\n";
    } else if (args[1] == "stepi" || args[1] == "si") {
        std::cout << "Single step an instruction\n";
    } else {
        std::cerr << "Unknown command: " << args[1] << '\n';
    }
}

// Helper function for print_help calls with initializer list
void print_help_init(std::initializer_list<std::string> args_list) {
    std::vector<std::string> args_vec(args_list);
    print_help(std::span<const std::string>(args_vec));
}

void handle_register_read(xdb::process &process,
                          std::span<const std::string> args) {
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
            auto is_gpr = info.type == xdb::register_type::gpr &&
                          info.id != xdb::register_id::orig_rax;
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
        print_help_init({"help", "register"});
    }
}

xdb::registers::value parse_register_value(const xdb::register_info &info,
                                           const std::string &value_str) {
    try {
        switch (info.format) {
            case xdb::register_format::uint:
                switch (info.size) {
                    case sizeof(std::uint8_t):
                        return xdb::to_integral<std::uint8_t>(value_str)
                            .value();
                    case sizeof(std::uint16_t):
                        return xdb::to_integral<std::uint16_t>(value_str)
                            .value();
                    case sizeof(std::uint32_t):
                        return xdb::to_integral<std::uint32_t>(value_str)
                            .value();
                    case sizeof(std::uint64_t):
                        return xdb::to_integral<std::uint64_t>(value_str)
                            .value();
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

void handle_register_write(xdb::process &process,
                           std::span<const std::string> args) {
    if (args.size() != 4) {
        print_help_init({"help", "register"});
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

void handle_register_command(xdb::process &process,
                             std::span<const std::string> args) {
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
        fmt::println("{}: address = {:#x}, {}", breakpoint_site.id(),
                     breakpoint_site.address().addr(),
                     breakpoint_site.is_enabled() ? "enabled" : "disabled");
    });
}

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
        fmt::println("{}: address = {:#x}, mode = {}, size = {}, {}",
                     watchpoint.id(), watchpoint.address().addr(), mode_str,
                     watchpoint.size(),
                     watchpoint.is_enabled() ? "enabled" : "disabled");
    });
}

void handle_breakpoint_command(xdb::process &process,
                               std::span<const std::string> args) {
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
        process.create_breakpoint_site(xdb::virt_addr{*address}, hardware)
            .enable();
        return;
    }

    if (args.size() < 3) {
        phelp();
        return;
    }
    auto breakpoint_id =
        xdb::to_integral<xdb::breakpoint_site::id_type>(args[2]);
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

void handle_watchpoint_command(xdb::process &process,
                               std::span<const std::string> args) {
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
            process.create_watchpoint(xdb::virt_addr{*address}, mode, *size)
                .enable();
            fmt::println("Watchpoint set at {:#x}", *address);
        } catch (const std::exception &e) {
            fmt::println("Error setting watchpoint: {}", e.what());
        }
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

void handle_memory_read(xdb::process &process,
                        std::span<const std::string> args) {
    constexpr std::size_t default_read_bytes = 32;
    constexpr std::size_t bytes_per_line = 16;

    if (args.size() < 3) {
        print_help_init({"help", "memory"});
        return;
    }

    constexpr int hex_base = 16;
    auto address = xdb::to_integral<std::uint64_t>(args[2], hex_base);
    if (!address) {
        std::cerr
            << "Invalid address format. Use 0x prefix for hex addresses.\n";
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
            for (std::size_t j = 0; j < bytes_per_line && i + j < data.size();
                 ++j) {
                fmt::print("{:02x} ", static_cast<std::uint8_t>(data[i + j]));
            }

            fmt::println("");
        }
    } catch (const xdb::error &e) {
        std::cerr << "Error reading memory: " << e.what() << '\n';
    }
}

void handle_memory_write(xdb::process &process,
                         std::span<const std::string> args) {
    if (args.size() < 4) {
        print_help_init({"help", "memory"});
        return;
    }

    constexpr int hex_base = 16;
    auto address = xdb::to_integral<std::uint64_t>(args[2], hex_base);
    if (!address) {
        std::cerr
            << "Invalid address format. Use 0x prefix for hex addresses.\n";
        return;
    }

    try {
        auto bytes = xdb::parse_vector(args[3]);
        if (bytes.empty()) {
            std::cerr << "No data to write.\n";
            return;
        }

        process.write_memory(xdb::virt_addr{*address},
                             std::span<const std::byte>(bytes));
        fmt::println("Successfully wrote {} bytes to {:#x}", bytes.size(),
                     *address);

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

void handle_memory_command(xdb::process &process,
                           std::span<const std::string> args) {
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

void handle_disassemble_command(xdb::process &process,
                                std::span<const std::string> args) {
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
                fmt::println(
                    "Invalid address format. Address is expected in "
                    "0xhex format.");
                return;
            }
            address = xdb::virt_addr{*addr};
            ++i;  // Skip the argument we just consumed
        }
    }

    print_disassembly(process, address, n_instructions);
}

void handle_command(std::unique_ptr<xdb::process> &process,
                    std::string_view line) {
    auto args = split(line, ' ');
    const auto &command = args[0];

    if (command == "help" || command == "h") {
        print_help(args);
    } else if (command == "breakpoint" || command == "b") {
        handle_breakpoint_command(*process, args);
    } else if (command == "watchpoint" || command == "w") {
        handle_watchpoint_command(*process, args);
    } else if (command == "continue" || command == "c") {
        if (process->state() == xdb::process_state::stopped) {
            process->resume();
            auto reason = process->wait_on_signal();
            handle_stop(*process, reason);
        } else {
            std::cerr
                << "Cannot continue because process state is not stopped\n";
        }
    } else if (command == "disassemble" || command == "disas") {
        handle_disassemble_command(*process, args);
    } else if (command == "memory" || command == "mem") {
        handle_memory_command(*process, args);
    } else if (command == "register" || command == "reg") {
        handle_register_command(*process, args);
    } else if (command == "stepi" || command == "si") {
        auto reason = process->step_instruction();
        handle_stop(*process, reason);
    }

    else {
        std::cerr << "Unknown command: " << command << '\n';
    }
}

}  // namespace

int run(std::span<const char *const> args) {
    if (args.size() < 2) {
        std::cerr << "No arguments given\n";
        return -1;
    }

    auto process = attach(args);
    std::cout << "Attached to process with PID: " << process->pid() << '\n';

    // REPL
    std::unique_ptr<char, decltype(&free)> line_ptr{nullptr, &free};
    using_history();
    while (auto *line = readline("xdb> ")) {
        line_ptr.reset(line);
        std::string line_string;
        if (std::string_view(line) == "") {
            // empty input is a shortcut for the last command
            if (history_length > 0) {
                line_string =
                    history_get(history_length)->line;  // 1-based index
            }
        } else {
            line_string = line;
            add_history(line);
        }

        if (!line_string.empty()) {
            handle_command(process, line_string);
        }
    }

    return 0;
}

int main(int argc, const char *argv[]) {
    try {
        std::span<const char *const> args(argv, static_cast<std::size_t>(argc));
        return run(args);
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << '\n';
        return -1;
    } catch (...) {
        std::cerr << "Unknown error occurred\n";
        return -1;
    }
}
