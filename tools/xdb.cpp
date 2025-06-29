#include <editline/readline.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <libxdb/process.hpp>
#include <memory>
#include <string_view>
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
    std::cout << "Process " << process.pid() << " ";
    const char *sig;
    switch (reason.state) {
        case xdb::process_state::running:
            std::cout << "is running";
            break;
        case xdb::process_state::stopped:
            sig = sigabbrev_np(reason.info);
            std::cout << "stopped by signal: " << (sig ? sig : "UNKNOWN");
            break;
        case xdb::process_state::exited:
            std::cout << "exited with status: " << reason.info;
            break;
        case xdb::process_state::terminated:
            sig = sigabbrev_np(reason.info);
            std::cout << "terminated by signal: " << (sig ? sig : "UNKNOWN");
            break;
        default:
            std::cerr << "state unknown";
    }
    std::cout << std::endl;
}

void handle_command(std::unique_ptr<xdb::process> &process,
                    std::string_view line) {
    auto args = split(line, ' ');
    auto command = args[0];

    if (command == "continue" || command == "c") {
        process->resume();
        auto reason = process->wait_on_signal();
        print_stop_reason(*process, reason);
    } else {
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