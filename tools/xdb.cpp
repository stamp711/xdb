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
#include <libxdb/syscalls.hpp>
#include <libxdb/target.hpp>
#include <libxdb/types.hpp>
#include <memory>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

#include "command/handlers.hpp"

namespace {

const xdb::process *&get_xdb_process() {
    static const xdb::process *g_xdb_process = nullptr;
    return g_xdb_process;
}

void handle_signal(int signum) {
    if (signum == SIGINT) {
        if (get_xdb_process() != nullptr) {
            ::kill(get_xdb_process()->pid(), SIGSTOP);
        }
    }
}

std::unique_ptr<xdb::target> attach(std::span<const char *const> args) {
    if (args.size() < 2) {
        std::cerr << "Usage: xdb [-p PID] [program_path]\n";
        return nullptr;
    }

    if (args.size() == 3 && args[1] == std::string_view("-p")) {
        // Attaching to a process by PID
        pid_t pid = static_cast<pid_t>(std::stoi(args[2]));
        return xdb::target::attach(pid);
    }

    std::filesystem::path path(args[1]);
    return xdb::target::launch(path);
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

std::string format_syscall_trap_info(const xdb::syscall_information &syscall) {
    if (syscall.is_entry) {
        return " (syscall entry)";
    }
    return " (syscall exit)";
}

void print_syscall_details(const xdb::syscall_information &syscall) {
    auto syscall_name = xdb::syscall_id_to_name(syscall.id);

    if (syscall.is_entry) {
        if (syscall.args.has_value()) {
            const auto &args = syscall.args.value();
            fmt::println("syscall entry: {}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})", syscall_name, args[0], args[1],
                         args[2], args[3], args[4], args[5]);
        } else {
            fmt::println("syscall entry: {}(...)", syscall_name);
        }
    } else {
        if (syscall.ret.has_value()) {
            fmt::println("syscall exit: {}(...) = {:#x}", syscall_name, syscall.ret.value());
        } else {
            fmt::println("syscall exit: {}(...)", syscall_name);
        }
    }
}

std::string get_sigtrap_info(const xdb::process &process, const xdb::stop_reason &reason) {
    std::string message;

    if (!reason.trap_reason.has_value()) {
        return message;
    }
    switch (reason.trap_reason.value()) {
        case xdb::trap_type::software_breakpoint: {
            const auto &bp = process.breakpoint_sites().get_by_address(process.get_pc());
            message = fmt::format(" (breakpoint {})", bp.id());
        } break;

        case xdb::trap_type::single_step: {
            message = " (single step)";
        } break;

        case xdb::trap_type::hardware_stoppoint: {
            auto id = process.get_current_hardware_stoppoint();
            if (id.index() == 0) {  // Hardware breakpoint
                message = fmt::format(" (breakpoint {})", std::get<0>(id));
            } else if (id.index() == 1) {  // Hardware watchpoint
                const auto watchpoint_id = std::get<1>(id);
                message = fmt::format(" (watchpoint {})", watchpoint_id);
                const auto &wp = process.watchpoints().get_by_id(watchpoint_id);
                if (wp.data() == wp.previous_data()) {
                    message += fmt::format("\n Value: {:#x}", wp.data());
                } else {
                    message += fmt::format("\n Previous Value: {:#x}", wp.previous_data());
                    message += fmt::format("\n Current Value: {:#x}", wp.data());
                }
            }
        } break;

        case xdb::trap_type::syscall: {
            if (reason.syscall_info.has_value()) {
                message = format_syscall_trap_info(reason.syscall_info.value());
            } else {
                message = " (syscall)";
            }
        } break;

        case xdb::trap_type::unknown: {
        } break;
    }

    if (reason.trap_reason == xdb::trap_type::software_breakpoint) {
        const auto &bp = process.breakpoint_sites().get_by_address(process.get_pc());
        message = fmt::format(" (breakpoint {})", bp.id());

    } else if (reason.trap_reason == xdb::trap_type::single_step) {
        message = " (single step)";

    } else if (reason.trap_reason == xdb::trap_type::hardware_stoppoint) {
        auto id = process.get_current_hardware_stoppoint();
        if (id.index() == 0) {  // Hardware breakpoint
            message = fmt::format(" (breakpoint {})", std::get<0>(id));
        } else if (id.index() == 1) {  // Hardware watchpoint
            const auto watchpoint_id = std::get<1>(id);
            message = fmt::format(" (watchpoint {})", watchpoint_id);
            const auto &wp = process.watchpoints().get_by_id(watchpoint_id);
            if (wp.data() == wp.previous_data()) {
                message += fmt::format("\n Value: {:#x}", wp.data());
            } else {
                message += fmt::format("\n Previous Value: {:#x}", wp.previous_data());
                message += fmt::format("\n Current Value: {:#x}", wp.data());
            }
        }
    }

    return message;
}

std::string generate_signal_stop_reason(const xdb::target &target, const xdb::stop_reason &reason) {
    auto message =
        fmt::format("stopped by signal {} at {:#x}", sigabbrev_np(reason.info), target.get_process().get_pc().addr());

    const auto *func = target.get_elf().get_symbol_containing_virt_addr(target.get_process().get_pc());

    if (func != nullptr && ELF64_ST_TYPE(func->st_info) == STT_FUNC) {
        auto func_name = target.get_elf().get_string(func->st_name);
        message += fmt::format("\n In function {}", func_name);
    }

    if (reason.info == SIGTRAP) {
        message += get_sigtrap_info(target.get_process(), reason);
    }
    return message;
}

void print_stop_reason(const xdb::target &target, const xdb::stop_reason &reason) {
    std::string message;
    switch (reason.state) {
        case xdb::process_state::running:
            message = "is running";
            break;
        case xdb::process_state::stopped:
            message = generate_signal_stop_reason(target, reason);
            break;
        case xdb::process_state::exited:
            message = fmt::format("exited with status {}", reason.info);
            break;
        case xdb::process_state::terminated:
            message = fmt::format("terminated by signal {}", sigabbrev_np(reason.info));
            break;
        default:
            message = "state is unknown";
    }
    fmt::println("Process {} {}", target.get_process().pid(), message);

    // Print additional syscall details if this is a syscall trap
    if (reason.state == xdb::process_state::stopped && reason.info == SIGTRAP &&
        reason.trap_reason == xdb::trap_type::syscall && reason.syscall_info.has_value()) {
        print_syscall_details(reason.syscall_info.value());
    }
}

void handle_stop(xdb::target &target, xdb::stop_reason reason) {
    print_stop_reason(target, reason);
    if (reason.state == xdb::process_state::stopped) {
        constexpr std::size_t instr_cnt = 5;
        xdb_handlers::print_disassembly(target.get_process(), target.get_process().get_pc(), instr_cnt);
    }
}

void handle_command(std::unique_ptr<xdb::target> &target, std::string_view line) {
    auto args = split(line, ' ');
    const auto &command = args[0];
    auto *process = &target->get_process();

    if (command == "help" || command == "h") {
        xdb_handlers::print_help(args);
    } else if (command == "breakpoint" || command == "b") {
        xdb_handlers::handle_breakpoint_command(*process, args);
    } else if (command == "catchpoint" || command == "catch") {
        xdb_handlers::handle_catchpoint_command(*process, args);
    } else if (command == "watchpoint" || command == "w") {
        xdb_handlers::handle_watchpoint_command(*process, args);
    } else if (command == "continue" || command == "c") {
        if (process->state() == xdb::process_state::stopped) {
            process->resume();
            auto reason = process->wait_on_signal();
            handle_stop(*target, reason);
        } else {
            std::cerr << "Cannot continue because process state is not stopped\n";
        }
    } else if (command == "disassemble" || command == "disas") {
        xdb_handlers::handle_disassemble_command(*process, args);
    } else if (command == "memory" || command == "mem") {
        xdb_handlers::handle_memory_command(*process, args);
    } else if (command == "register" || command == "reg") {
        xdb_handlers::handle_register_command(*process, args);
    } else if (command == "stepi" || command == "si") {
        auto reason = process->step_instruction();
        handle_stop(*target, reason);
    }

    else {
        std::cerr << "Unknown command: " << command << '\n';
    }
}

int run(std::span<const char *const> args) {
    if (args.size() < 2) {
        std::cerr << "No arguments given\n";
        return -1;
    }

    auto target = attach(args);

    // Register signal handler
    get_xdb_process() = &target->get_process();
    signal(SIGINT, handle_signal);

    std::cout << "Attached to process with PID: " << target->get_process().pid() << '\n';

    // REPL
    std::unique_ptr<char, decltype(&free)> line_ptr{nullptr, &free};
    using_history();
    while (auto *line = readline("xdb> ")) {
        line_ptr.reset(line);
        std::string line_string;
        if (std::string_view(line) == "") {
            // empty input is a shortcut for the last command
            if (history_length > 0) {
                line_string = history_get(history_length)->line;  // 1-based index
            }
        } else {
            line_string = line;
            add_history(line);
        }

        if (!line_string.empty()) {
            handle_command(target, line_string);
        }
    }

    return 0;
}

}  // namespace

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
