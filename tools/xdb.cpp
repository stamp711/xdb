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
#include <iostream>
#include <libxdb/breakpoint_site.hpp>
#include <libxdb/disassembler.hpp>
#include <libxdb/parse.hpp>
#include <libxdb/process.hpp>
#include <libxdb/register_info.hpp>
#include <libxdb/registers.hpp>
#include <libxdb/types.hpp>
#include <memory>
#include <string_view>
#include <type_traits>
#include <vector>

namespace {

std::unique_ptr<xdb::process> attach(int argc, const char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: xdb [-p PID] [program_path]" << std::endl;
        return nullptr;
    }

    if (argc == 3 && argv[1] == std::string_view("-p")) {
        // Attaching to a process by PID
        pid_t pid = static_cast<pid_t>(std::stoi(argv[2]));
        return xdb::process::attach(pid);
    } else {
        // Passing program path
        std::filesystem::path path(argv[1]);
        return xdb::process::launch(path);
    }
}

std::vector<std::string> split(std::string_view str, char delimiter) {
    std::vector<std::string> tokens;
    size_t i = 0;
    while (i < str.size()) {
        auto j = str.find(delimiter, i);
        if (j == std::string_view::npos) {
            j = str.size();  // If no more delimiters, take the rest of the
                             // string
        }
        if (j > i) {
            // Only add non-empty tokens
            tokens.emplace_back(str.substr(i, j - i));
        }
        i = j + 1;
    }
    return tokens;
}

void print_stop_reason(const xdb::process &process,
                       const xdb::stop_reason &reason) {
    std::string message;
    const char *sig;
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
        print_disassembly(process, process.get_pc(), 5);
    }
}

void print_help(const std::vector<std::string> &args) {
    if (args.size() == 1) {
        std::cout << "Available commands:\n"
                  << "    help, h            - Show this help message\n"
                  << "    breakpoint, b      - Manage breakpoints\n"
                  << "    continue, c        - Resume the process\n"
                  << "    disassemble, disas - Disassemble instructions\n"
                  << "    memory, mem        - Memory operations\n"
                  << "    register, reg      - Register operations\n"
                  << "    stepi, si          - Single step an instruction\n";
    } else if (args[1] == "breakpoint") {
        std::cout
            << "Manage breakpoints.\n"
            << "Usage:\n"
            << "    breakpoint list             - List all breakpoints\n"
            << "    breakpoint set <address>    - Set a breakpoint at the "
               "specified address\n"
            << "    breakpoint enable <id>      - Enable a breakpoint by ID\n"
            << "    breakpoint disable <id>     - Disable a breakpoint by ID\n"
            << "    breakpoint delete <id>      - Delete a breakpoint by ID\n";
    } else if (args[1] == "continue") {
        std::cout << "Resume the process.\n";
    } else if (args[1] == "disassemble") {
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
    } else if (args[1] == "memory") {
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
    } else if (args[1] == "register") {
        std::cout << "Usage:\n"
                  << "    register read\n"
                  << "    register read <register>\n"
                  << "    register read all\n"
                  << "    register write <register> <value>\n";
    } else if (args[1] == "stepi") {
        std::cout << "Single step an instruction\n";
    } else {
        std::cerr << "Unknown command: " << args[1] << std::endl;
    }
}

void handle_register_read(xdb::process &process,
                          const std::vector<std::string> &args) {
    auto format = [](auto t) {
        if constexpr (std::is_floating_point_v<decltype(t)>) {
            return fmt::format("{}", t);
        } else if constexpr (std::is_integral_v<decltype(t)>) {
            return fmt::format("{:#0{}x}", t, sizeof(t) * 2 + 2);
        } else {  // byte64 & byte128 -> std::array<std::byte, _>
            return fmt::format("[{:#04x}]", fmt::join(t, ", "));
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
            std::cerr << "No such register" << std::endl;
        }
    } else {
        print_help({"help", "register"});
    }
}

xdb::registers::value parse_register_value(const xdb::register_info &info,
                                           const std::string &s) {
    try {
        switch (info.format) {
            case xdb::register_format::uint:
                switch (info.size) {
                    case 1:
                        return xdb::to_integral<std::uint8_t>(s).value();
                    case 2:
                        return xdb::to_integral<std::uint16_t>(s).value();
                    case 4:
                        return xdb::to_integral<std::uint32_t>(s).value();
                    case 8:
                        return xdb::to_integral<std::uint64_t>(s).value();
                }
                break;
            case xdb::register_format::double_float:
                return xdb::to_float<double>(s).value();
            case xdb::register_format::long_double:
                return xdb::to_float<long double>(s).value();
            case xdb::register_format::vector:
                if (info.size == 8) {
                    return xdb::parse_vector<8>(s);
                }
        }
    } catch (...) {
    }
    xdb::error::send("Invalid format");
}

void handle_register_write(xdb::process &process,
                           const std::vector<std::string> &args) {
    if (args.size() != 4) {
        print_help({"help", "register"});
        return;
    }
    try {
        auto info = xdb::register_info_by_name(args[2]);
        auto value = parse_register_value(info, args[3]);
        process.get_registers().write(info, value);
    } catch (const xdb::error &e) {
        std::cerr << "Error writing to register: " << e.what() << std::endl;
    }
}

void handle_register_command(xdb::process &process,
                             const std::vector<std::string> &args) {
    if (args.size() < 2) {
        print_help({"help", "register"});
    } else if (args[1] == "read") {
        handle_register_read(process, args);
    } else if (args[1] == "write") {
        handle_register_write(process, args);
    } else {
        print_help({"help", "register"});
    }
}

void handle_breakpoint_command(xdb::process &process,
                               const std::vector<std::string> args) {
    auto phelp = []() { print_help({"help", "breakpoint"}); };

    if (args.size() < 2) {
        phelp();
        return;
    }

    auto cmd = args[1];
    if (cmd == "list") {
        if (process.breakpoint_sites().empty()) {
            fmt::println("No breakpoints set.");
        } else {
            fmt::println("Breakpoints:");
            process.breakpoint_sites().for_each([](const auto &bp) {
                fmt::println("{}: address = {:#x}, {}", bp.id(),
                             bp.address().addr(),
                             bp.is_enabled() ? "enabled" : "disabled");
            });
        }
        return;
    } else if (cmd == "set") {
        if (args.size() < 3) {
            phelp();
            return;
        }
        auto address = xdb::to_integral<std::uint64_t>(args[2], 16);
        if (!address) {
            fmt::println("Address is expected in 0xhex format");
            return;
        }
        process.create_breakpoint_site(xdb::virt_addr{*address}).enable();
        return;
    }

    if (args.size() < 3) {
        phelp();
        return;
    }
    auto id = xdb::to_integral<xdb::breakpoint_site::id_type>(args[2]);
    if (!id) {
        fmt::println("Command expects valid breakpoint ID");
        return;
    }

    if (cmd == "enable") {
        process.breakpoint_sites().get_by_id(*id).enable();
    } else if (cmd == "disable") {
        process.breakpoint_sites().get_by_id(*id).disable();
    } else if (cmd == "delete") {
        process.breakpoint_sites().remove_by_id(*id);
    } else {
        fmt::println("Unknown breakpoint command: {}", cmd);
        phelp();
    }
}

void handle_memory_read(xdb::process &process,
                        const std::vector<std::string> &args) {
    if (args.size() < 3) {
        print_help({"help", "memory"});
        return;
    }

    auto address = xdb::to_integral<std::uint64_t>(args[2], 16);
    if (!address) {
        std::cerr << "Invalid address format. Use 0x prefix for hex addresses."
                  << std::endl;
        return;
    }

    std::size_t size = 32;  // Default size
    if (args.size() >= 4) {
        auto size_opt = xdb::to_integral<std::size_t>(args[3]);
        if (!size_opt) {
            std::cerr << "Invalid size value." << std::endl;
            return;
        }
        size = *size_opt;
    }

    try {
        auto data = process.read_memory(xdb::virt_addr{*address}, size);

        // Print in hex dump format (16 bytes per line, no ASCII)
        for (std::size_t i = 0; i < data.size(); i += 16) {
            fmt::print("{:#016x}: ", *address + i);

            // Print hex bytes (max 16 per line)
            for (std::size_t j = 0; j < 16 && i + j < data.size(); ++j) {
                fmt::print("{:02x} ", static_cast<std::uint8_t>(data[i + j]));
            }

            fmt::println("");
        }
    } catch (const xdb::error &e) {
        std::cerr << "Error reading memory: " << e.what() << std::endl;
    }
}

void handle_memory_write(xdb::process &process,
                         const std::vector<std::string> &args) {
    if (args.size() < 4) {
        print_help({"help", "memory"});
        return;
    }

    auto address = xdb::to_integral<std::uint64_t>(args[2], 16);
    if (!address) {
        std::cerr << "Invalid address format. Use 0x prefix for hex addresses."
                  << std::endl;
        return;
    }

    try {
        auto bytes = xdb::parse_vector(args[3]);
        if (bytes.empty()) {
            std::cerr << "No data to write." << std::endl;
            return;
        }

        process.write_memory(xdb::virt_addr{*address},
                             std::span<const std::byte>(bytes));
        fmt::println("Successfully wrote {} bytes to {:#x}", bytes.size(),
                     *address);

        // Show what was written
        fmt::print("Data written: [");
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            if (i > 0) fmt::print(",");
            fmt::print("{:#04x}", static_cast<std::uint8_t>(bytes[i]));
        }
        fmt::println("]");

    } catch (const xdb::error &e) {
        std::cerr << "Error writing memory: " << e.what() << std::endl;
    }
}

void handle_memory_command(xdb::process &process,
                           const std::vector<std::string> &args) {
    if (args.size() < 2) {
        print_help({"help", "memory"});
    } else if (args[1] == "read") {
        handle_memory_read(process, args);
    } else if (args[1] == "write") {
        handle_memory_write(process, args);
    } else {
        print_help({"help", "memory"});
    }
}

void handle_disassemble_command(xdb::process &process,
                                const std::vector<std::string> &args) {
    auto address = process.get_pc();
    std::size_t n_instructions = 5;

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
            auto addr = xdb::to_integral<std::uint64_t>(args[i + 1], 16);
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
    } else if (command == "continue" || command == "c") {
        process->resume();
        auto reason = process->wait_on_signal();
        handle_stop(*process, reason);
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
        std::cerr << "Unknown command: " << command << std::endl;
    }
}

}  // namespace

int run(int argc, const char *argv[]) {
    if (argc < 2) {
        std::cerr << "No arguments given" << std::endl;
        return -1;
    }

    auto process = attach(argc, argv);
    std::cout << "Attached to process with PID: " << process->pid()
              << std::endl;

    // REPL
    char *line = nullptr;
    while ((line = readline("xdb> ")) != nullptr) {
        std::string line_string;
        if (line == std::string_view("")) {
            free(line);
            // empty input is a shortcut for the last command
            if (history_length > 0) {
                line_string = history_list()[history_length - 1]->line;
            }
        } else {
            line_string = line;
            add_history(line);
            free(line);
        }

        if (!line_string.empty()) {
            handle_command(process, line_string);
        }
    }

    return 0;
}

int main(int argc, const char *argv[]) {
    try {
        return run(argc, argv);
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return -1;
    } catch (...) {
        std::cerr << "Unknown error occurred" << std::endl;
        return -1;
    }
}
