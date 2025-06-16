#include <cstdio>
#include <cstdlib>
#include <editline/readline.h>
#include <fcntl.h>
#include <iostream>
#include <optional>
#include <string_view>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {
std::optional<pid_t> fork_exec(const char* path)
{
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        std::perror("pipe failed");
        return std::nullopt;
    }

    std::optional<pid_t> pid = std::nullopt;

    if ((pid = fork()) < 0) {
        std::cerr << "Fork failed" << std::endl;
        return std::nullopt;
    }

    if (pid == 0) {
        // Child process
        close(pipefd[0]); // Close read end of the pipe

        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
            std::perror("PTRACE_TRACEME failed");
            write(pipefd[1], "X", 1); // Write error message to pipe
            std::exit(-1);
        }

        fcntl(pipefd[1], F_SETFD, fcntl(pipefd[1], F_GETFD) | FD_CLOEXEC); // Set close-on-exec flag

        execlp(path, path, nullptr);

        std::perror("Exec failed");
        write(pipefd[1], "X", 1); // Write error message to pipe
        std::exit(-1); // Exit child process
    } else {
        // Parent process
        close(pipefd[1]); // Close write end of the pipe

        char buf;
        ssize_t n = read(pipefd[0], &buf, 1);
        close(pipefd[0]); // Close read end of the pipe

        if (n == 0) {
            // Child process exec succeeded
            return pid;
        } else {
            // Child process exec failed
            std::cerr << "Exec failed in child process" << std::endl;
            return std::nullopt;
        }
    }
}

std::optional<pid_t> attach(int argc, const char* argv[])
{
    std::optional<pid_t> pid = std::nullopt;

    if (argc == 3 && argv[1] == std::string_view("-p")) {
        // Attaching to a process by PID
        pid = static_cast<pid_t>(std::stoi(argv[2]));
        if (pid <= 0) {
            std::cerr << "Invalid PID: " << argv[2] << std::endl;
            return std::nullopt;
        }
        if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
            std::perror("PTRACE_ATTACH failed");
            return std::nullopt;
        }
    } else {
        // Passing program path
        const char* program_path = argv[1];
        return fork_exec(program_path);
    }

    return pid;
}

std::vector<std::string> split(std::string_view str, char delimiter)
{
    std::vector<std::string> tokens;
    size_t i = 0;
    while (i < str.size()) {
        auto j = str.find(delimiter, i);
        if (j == std::string_view::npos) {
            j = str.size(); // If no more delimiters, take the rest of the string
        }
        if (j > i) {
            // Only add non-empty tokens
            tokens.emplace_back(str.substr(i, j - i));
        }
        i = j + 1;
    }
    return tokens;
}

void resume(pid_t pid)
{
    if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0) {
        std::perror("PTRACE_CONT failed");
        std::exit(-1);
    }
}

void wait_on_signal(pid_t pid)
{
    int wait_status;
    if (waitpid(pid, &wait_status, 0) < 0) {
        std::perror("waitpid failed");
        std::exit(-1);
    }
}

void handle_command(pid_t pid, std::string_view line)
{
    auto args = split(line, ' ');
    auto command = args[0];

    if (command == "continue" || command == "c") {
        resume(pid);
        wait_on_signal(pid);
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
    }
}
} // namespace

int main(int argc, const char* argv[])
{
    if (argc < 2) {
        std::cerr << "No arguments given" << std::endl;
        return -1;
    }

    auto opt_pid = attach(argc, argv);
    if (!opt_pid) {
        std::cerr << "Failed to attach to process." << std::endl;
        return -1;
    }
    pid_t pid = *opt_pid;
    std::cout << "Attached to process with PID: " << pid << std::endl;

    int wait_status;
    if (waitpid(pid, &wait_status, 0) < 0) {
        std::perror("waitpid failed");
        return -1;
    }
    if (WIFSTOPPED(wait_status)) {
        std::cout << "Successfully attached and stopped process." << std::endl;
    } else {
        std::cerr << "Process did not stop as expected after attach." << std::endl;
    }

    // REPL
    char* line = nullptr;
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
            handle_command(pid, line_string);
        }
    }

    return 0;
}