#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <iostream>
#include <libxdb/error.hpp>
#include <libxdb/process.hpp>
#include <memory>

namespace xdb {

std::unique_ptr<process> process::attach(pid_t pid) {
    // Attaching to a process by PID
    if (pid <= 0) {
        error::send("Invalid PID");
    }

    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
        error::send_errno("PTRACE_ATTACH failed");
    }

    std::unique_ptr<process> proc(new process(pid, false));
    proc->wait_on_signal();

    return proc;
}

std::unique_ptr<process> process::launch(std::filesystem::path path) {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        error::send_errno("pipe failed");
    }

    pid_t pid = fork();
    if (pid < 0) {
        error::send_errno("fork failed");
    }

    if (pid == 0) {
        // Child process
        try {
            // Close read-end of the pipe
            close(pipefd[0]);
            // Close-on-exec for the write-end
            fcntl(pipefd[1], F_SETFD, fcntl(pipefd[1], F_GETFD) | FD_CLOEXEC);

            // TRACEME
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
                error::send_errno("PTRACE_TRACEME failed");
            }

            // Exec
            execlp(path.c_str(), path.c_str(), nullptr);
            error::send_errno("Exec failed");

        } catch (const std::exception &e) {
            // Catch all exceptions in child process
            write(pipefd[1], "X", 1);  // Write error message to pipe
            std::cerr << "Exception in forked child process: " << e.what()
                      << std::endl;
            std::exit(-1);  // Exit child process
        }
    }

    // Parent process
    close(pipefd[1]);  // Close write end of the pipe
    char buf;
    ssize_t n = read(pipefd[0], &buf, 1);
    close(pipefd[0]);  // Close read end of the pipe

    if (n != 0) {  // -1 is error, 0 is EOF
        error::send("Child process exec failed");
    }

    // Child process exec succeeded
    std::unique_ptr<process> proc(new process(pid, true));
    proc->wait_on_signal();
    return proc;
}

process::~process() {
    if (pid_ <= 0) {
        return;
    }

    // If the process is running, we need to stop it before detaching
    if (state_ == process_state::running) {
        kill(pid_, SIGSTOP);
        waitpid(pid_, nullptr, 0);
    }

    // Detach from the process
    if (ptrace(PTRACE_DETACH, pid_, nullptr, nullptr) == -1) {
        std::cerr << "WARN: PTRACE_DETACH failed for PID " << pid_ << ": "
                  << strerror(errno) << std::endl;
    }

    // Terminate the process if needed
    if (terminate_on_destruction_) {
        // If the process is set to terminate on destruction, we kill it
        if (kill(pid_, SIGKILL) == -1) {
            std::cerr << "WARN: Failed to kill process " << pid_ << ": "
                      << strerror(errno) << std::endl;
        }
        waitpid(pid_, nullptr, 0);
    }
}

void process::resume() {
    if (ptrace(PTRACE_CONT, pid_, nullptr, nullptr) == -1) {
        error::send_errno("PTRACE_CONT failed");
    }
    state_ = process_state::running;
}

stop_reason process::wait_on_signal() {
    int wait_status;
    if (waitpid(pid_, &wait_status, 0) < 0) {
        error::send_errno("waitpid failed");
    }

    // Update the process state based on the wait status
    stop_reason reason(wait_status);
    state_ = reason.state;
    return reason;
}

stop_reason::stop_reason(int wait_status) {
    if (WIFSTOPPED(wait_status)) {
        state = process_state::stopped;
        info = WSTOPSIG(wait_status);

    } else if (WIFEXITED(wait_status)) {
        state = process_state::exited;
        info = WEXITSTATUS(wait_status);

    } else if (WIFSIGNALED(wait_status)) {
        state = process_state::terminated;
        info = WTERMSIG(wait_status);

    } else {
        state = process_state::stopped;  // Default case
        info = 0;
    }
}

}  // namespace xdb