#include <fcntl.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <libxdb/breakpoint_site.hpp>
#include <libxdb/error.hpp>
#include <libxdb/pipe.hpp>
#include <libxdb/process.hpp>
#include <libxdb/register_info.hpp>
#include <libxdb/types.hpp>
#include <memory>
#include <string>

std::unique_ptr<xdb::process> xdb::process::attach(pid_t pid) {
    // Attaching to a process by PID
    if (pid <= 0) {
        error::send("Invalid PID");
    }

    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
        error::send_errno("PTRACE_ATTACH failed");
    }

    std::unique_ptr<process> proc(new process(pid, false, true));
    proc->wait_on_signal();

    return proc;
}

void exit_with_perror(xdb::pipe &p, const std::string &prefix) {
    auto message = prefix + ": " + strerror(errno);
    p.write(reinterpret_cast<const std::byte *>(message.data()),
            message.size());
    p.close_write();
    ::exit(-1);
}

std::unique_ptr<xdb::process> xdb::process::launch(
    std::filesystem::path path, bool debug,
    std::optional<int> stdout_replacement) {
    pipe p(true);  // Create a pipe with close-on-exec

    pid_t pid = fork();
    if (pid < 0) {
        error::send_errno("fork failed");
    }

    if (pid == 0) {
        // Child process
        p.close_read();

        ::personality(ADDR_NO_RANDOMIZE);  // Disable ASLR

        if (stdout_replacement) {
            // Redirect stdout to the specified file descriptor
            if (::dup2(*stdout_replacement, STDOUT_FILENO) == -1) {
                exit_with_perror(p, "dup2 failed for stdout");
            }
        }

        if (debug && ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
            exit_with_perror(p, "PTRACE_TRACEME failed");
        }

        execlp(path.c_str(), path.c_str(), nullptr);
        exit_with_perror(p, "Exec failed");
    }

    // Parent process
    p.close_write();  // Close write so our read() won't block
    auto data = p.read();
    p.close_read();

    if (!data.empty()) {
        waitpid(pid, nullptr, 0);  // Wait for child to exit
        auto child_message = std::string(data.begin(), data.end());
        error::send("Child process error: " + child_message);
    }

    // Child process exec succeeded
    std::unique_ptr<process> proc(new process(pid, true, debug));
    if (debug) proc->wait_on_signal();
    return proc;
}

xdb::process::~process() {
    if (pid_ <= 0) {
        return;
    }

    if (is_attached_) {
        // If the process is running, we need to stop it before detaching
        if (state_ == process_state::running) {
            kill(pid_, SIGSTOP);
            waitpid(pid_, nullptr, 0);
        }
        ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
        kill(pid_, SIGCONT);
    }

    // Terminate the process if needed
    if (terminate_on_destruction_) {
        // If the process is set to terminate on destruction, we kill it
        kill(pid_, SIGKILL);
        waitpid(pid_, nullptr, 0);
    }
}

void xdb::process::resume() {
    // Single step the breakpoint if it was hit
    auto pc = get_pc();
    if (breakpoint_sites_.enabled_stoppoint_address(pc)) {
        auto &bp = breakpoint_sites_.get_by_address(pc);
        bp.disable();  // Disable the breakpoint
        // Single step the process
        if (ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr) == -1) {
            error::send_errno("PTRACE_SINGLESTEP failed");
        }
        // Wait for the process to stop again
        if (waitpid(pid_, nullptr, 0) < 0) {
            error::send_errno("waitpid failed");
        }
        bp.enable();  // Re-enable the breakpoint
    }

    if (ptrace(PTRACE_CONT, pid_, nullptr, nullptr) == -1) {
        error::send_errno("PTRACE_CONT failed");
    }
    state_ = process_state::running;
}

xdb::stop_reason xdb::process::wait_on_signal() {
    int wait_status;
    if (waitpid(pid_, &wait_status, 0) < 0) {
        error::send_errno("waitpid failed");
    }

    // Update the process state based on the wait status
    stop_reason reason(wait_status);
    state_ = reason.state;

    // If the process is stopped, read all registers
    if (is_attached_ && state_ == process_state::stopped) {
        read_all_registers();

        // If stop caused by a xdb breakpoint, revert pc to breakpoint address
        // NOTE: if the breakpoint is not created by xdb, pc will remain to be
        // the next instruction
        auto prev = get_pc() - 1;
        if (reason.info == SIGTRAP &&
            breakpoint_sites_.enabled_stoppoint_address(prev)) {
            set_pc(prev);
        }
    }

    return reason;
}

xdb::stop_reason xdb::process::step_instruction() {
    // If we are stopped at a breakpoint, restore it to the original instruction
    // before stepping
    auto pc = get_pc();
    std::optional<breakpoint_site *> bp_to_reenable;
    if (breakpoint_sites_.enabled_stoppoint_address(pc)) {
        auto &bp = breakpoint_sites_.get_by_address(pc);
        bp.disable();
        bp_to_reenable = &bp;
        ::printf("disabled");
    }

    if (::ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr) == -1) {
        error::send_errno("PTRACE_SINGLESTEP failed");
    }
    auto reason = wait_on_signal();

    // Re-enable the breakpoint
    if (bp_to_reenable) {
        (*bp_to_reenable)->enable();
        ::printf("enabled");
    }

    return reason;
}

xdb::stop_reason::stop_reason(int wait_status) {
    if (WIFSTOPPED(wait_status)) {
        state = process_state::stopped;
        info = static_cast<uint8_t>(WSTOPSIG(wait_status));

    } else if (WIFEXITED(wait_status)) {
        state = process_state::exited;
        info = static_cast<uint8_t>(WEXITSTATUS(wait_status));

    } else if (WIFSIGNALED(wait_status)) {
        state = process_state::terminated;
        info = WTERMSIG(wait_status);

    } else {
        state = process_state::stopped;  // Default case
        info = 0;
    }
}

void xdb::process::read_all_registers() {
    // Read general-purpose registers
    if (ptrace(PTRACE_GETREGS, pid_, nullptr, &get_registers().data_.regs) ==
        -1) {
        error::send_errno("PTRACE_GETREGS failed");
    }

    // Read floating-point registers
    if (ptrace(PTRACE_GETFPREGS, pid_, nullptr, &get_registers().data_.i387) ==
        -1) {
        error::send_errno("PTRACE_GETFPREGS failed");
    }

    // Read debug registers
    for (int i = 0; i < 8; ++i) {
        auto id = static_cast<int>(register_id::dr0) + i;
        auto offset = register_info_by_id(static_cast<register_id>(id)).offset;

        errno = 0;  // Reset errno before each ptrace call
        std::uint64_t data = static_cast<std::uint64_t>(
            ptrace(PTRACE_PEEKUSER, pid_, offset, nullptr));
        if (errno != 0) {
            error::send_errno("PTRACE_PEEKUSER failed for debug register");
        }

        get_registers().data_.u_debugreg[i] = data;
    }
}

void xdb::process::write_user_area(std::size_t offset, std::uint64_t data) {
    if (ptrace(PTRACE_POKEUSER, pid_, offset, data) == -1) {
        error::send_errno("PTRACE_POKEUSER failed");
    }
}

void xdb::process::write_gprs(const user_regs_struct &gprs) {
    if (ptrace(PTRACE_SETREGS, pid_, nullptr, &gprs) == -1) {
        error::send_errno("PTRACE_SETREGS failed");
    }
}

void xdb::process::write_fprs(const user_fpregs_struct &fprs) {
    if (ptrace(PTRACE_SETFPREGS, pid_, nullptr, &fprs) == -1) {
        error::send_errno("PTRACE_SETFPREGS failed");
    }
}

std::vector<std::byte> xdb::process::read_memory(virt_addr addr,
                                                 std::size_t size) const {
    // Prepare data buffer and local iovec
    std::vector<std::byte> data(size);
    ::iovec local_iov = {.iov_base = data.data(), .iov_len = data.size()};

    // Allocate remote iovecs for each page
    std::vector<::iovec> remote_iovs;
    while (size > 0) {
        auto size_to_next_page_boundary = 0x1000 - (addr.addr() & 0xfff);
        auto iov_len = std::min(size, size_to_next_page_boundary);
        remote_iovs.emplace_back(
            ::iovec{.iov_base = reinterpret_cast<void *>(addr.addr()),
                    .iov_len = iov_len});

        addr += iov_len;
        size -= iov_len;
    }

    if (::process_vm_readv(pid_, &local_iov, 1, remote_iovs.data(),
                           remote_iovs.size(), 0) == -1) {
        error::send_errno("process_vm_readv failed");
    }

    return data;
}

void xdb::process::write_memory(virt_addr addr,
                                std::span<const std::byte> data) {
    // We use PTRACE_POKEDATA here because it can write to PROT_READ or
    // PROT_EXEC (i.e. not writable) memory. However, it can only write exactly
    // 8 bytes at a time.
    while (!data.empty()) {
        // Write one word at a time
        auto word_start = addr.align_to_word();
        auto offset = addr - word_start;  // Offset of addr within the word
        auto word_end = word_start + 8;

        auto end_addr = std::min(word_end, addr + data.size());
        auto size = end_addr - addr;  // size of the data to write in the word

        uint64_t word = 0;

        if (word_start < addr || end_addr < word_end) {
            // Read the original word
            errno = 0;
            word = static_cast<uint64_t>(
                ::ptrace(PTRACE_PEEKDATA, pid_, word_start.addr(), nullptr));
            if (errno != 0) {
                error::send_errno("ptrace PEEKDATA failed");
            }
        }

        // Copy the data into the word to write
        std::memcpy(reinterpret_cast<char *>(&word) + offset, data.data(),
                    size);

        if (::ptrace(PTRACE_POKEDATA, pid_, word_start.addr(), word) == -1) {
            error::send_errno("ptrace POKEDATA failed");
        }

        addr = end_addr;
        data = data.subspan(size);
    }
}

xdb::breakpoint_site &xdb::process::create_breakpoint_site(virt_addr address) {
    if (breakpoint_sites_.contains_address(address)) {
        error::send("Breakpoint site already exists at address " +
                    std::to_string(address.addr()));
    }
    auto bp_site =
        std::unique_ptr<breakpoint_site>(new breakpoint_site(*this, address));
    return breakpoint_sites_.push(std::move(bp_site));
}
