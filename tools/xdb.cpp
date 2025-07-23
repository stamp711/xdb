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
#include <libxdb/parse.hpp>
#include <libxdb/process.hpp>
#include <libxdb/register_info.hpp>
#include <libxdb/registers.hpp>
#include <memory>
#include <string_view>
#include <type_traits>
#include <vector>

#include "libxdb/breakpoint_site.hpp"
#include "libxdb/types.hpp"

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

void print_help(const std::vector<std::string> &args) {
    if (args.size() == 1) {
        std::cout << "Available commands:\n"
                  << "    help, h          - Show this help message\n"
                  << "    breakpoint, b    - Manage breakpoints\n"
                  << "    continue, c      - Resume the process\n"
                  << "    register, reg    - Register operations\n"
                  << "    stepi, si        - Single step an instruction\n";
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

void handle_command(std::unique_ptr<xdb::process> &process,
                    std::string_view line) {
    auto args = split(line, ' ');
    auto command = args[0];

    if (command == "help" || command == "h") {
        print_help(args);
    } else if (command == "breakpoint" || command == "b") {
        handle_breakpoint_command(*process, args);
    } else if (command == "continue" || command == "c") {
        process->resume();
        auto reason = process->wait_on_signal();
        print_stop_reason(*process, reason);
    } else if (command == "register" || command == "reg") {
        handle_register_command(*process, args);
    } else if (command == "stepi" || command == "si") {
        auto reason = process->step_instruction();
        print_stop_reason(*process, reason);
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
