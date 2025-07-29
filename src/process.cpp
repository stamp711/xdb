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
#include <libxdb/watchpoint.hpp>
#include <memory>
#include <string>

namespace {

constexpr std::size_t WORD_SIZE = 8;

// Returns 0/1/2/3, or throw an exception if there's no free space
int find_free_stoppoint_register(std::uint64_t control) {
    for (int i = 0; i < 4; ++i) {
        if ((control & (0b11ULL << (2 * i))) == 0) {
            return i;
        }
    }
    xdb::error::send("No free stoppoint register available");
}

std::uint64_t encode_hardware_stoppoint_mode(xdb::stoppoint_mode mode) {
    switch (mode) {
        case xdb::stoppoint_mode::execute:
            return 0b00;
        case xdb::stoppoint_mode::write:
            return 0b01;
        case xdb::stoppoint_mode::read_write:
            return 0b11;
        default:
            xdb::error::send("Invalid stoppoint mode");
    }
}

std::uint64_t encode_hardware_stoppoint_size(std::size_t size) {
    constexpr std::size_t BYTES_1 = 1;
    constexpr std::size_t BYTES_2 = 2;
    constexpr std::size_t BYTES_8 = 8;
    constexpr std::size_t BYTES_4 = 4;
    switch (size) {
        case BYTES_1:
            return 0b00;
        case BYTES_2:
            return 0b01;
        case BYTES_8:
            return 0b10;
        case BYTES_4:
            return 0b11;
        default:
            xdb::error::send("Invalid stoppoint size");
    }
}

}  // namespace

namespace xdb {

std::unique_ptr<process> process::attach(pid_t pid) {
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

void exit_with_perror(pipe &p, const std::string &prefix) {
    auto message = prefix + ": " + strerror(errno);
    p.write(reinterpret_cast<const std::byte *>(message.data()), message.size());
    p.close_write();
    ::exit(-1);
}

std::unique_ptr<process> process::launch(const std::filesystem::path &path, bool debug,
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

process::~process() {
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

void process::resume() {
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

stop_reason process::wait_on_signal() {
    int wait_status = 0;
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
        if (reason.info == SIGTRAP && breakpoint_sites_.enabled_stoppoint_address(prev)) {
            set_pc(prev);
        }
    }

    return reason;
}

stop_reason process::step_instruction() {
    // If we are stopped at a breakpoint, restore it to the original instruction
    // before stepping
    auto pc = get_pc();
    std::optional<breakpoint_site *> bp_to_reenable;
    if (breakpoint_sites_.enabled_stoppoint_address(pc)) {
        auto &bp = breakpoint_sites_.get_by_address(pc);
        bp.disable();
        bp_to_reenable = &bp;
    }

    if (::ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr) == -1) {
        error::send_errno("PTRACE_SINGLESTEP failed");
    }
    auto reason = wait_on_signal();

    // Re-enable the breakpoint
    if (bp_to_reenable) {
        (*bp_to_reenable)->enable();
    }

    return reason;
}

stop_reason::stop_reason(int wait_status) {
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

void process::read_all_registers() {
    // Read general-purpose registers
    if (ptrace(PTRACE_GETREGS, pid_, nullptr, &get_registers().data_.regs) == -1) {
        error::send_errno("PTRACE_GETREGS failed");
    }

    // Read floating-point registers
    if (ptrace(PTRACE_GETFPREGS, pid_, nullptr, &get_registers().data_.i387) == -1) {
        error::send_errno("PTRACE_GETFPREGS failed");
    }

    // Read debug registers
    // Template helper to read a single debug register at compile-time index
    auto read_debug_register = [this]<int I>() {
        auto id = static_cast<int>(register_id::dr0) + I;
        auto offset = register_info_by_id(static_cast<register_id>(id)).offset;

        errno = 0;  // Reset errno before each ptrace call
        auto data = static_cast<std::uint64_t>(ptrace(PTRACE_PEEKUSER, pid_, offset, nullptr));
        if (errno != 0) {
            error::send_errno("PTRACE_PEEKUSER failed for debug register");
        }

        get_registers().data_.u_debugreg[I] = data;
    };

    // Read all debug registers using fold expression
    constexpr int DEBUG_REGISTER_COUNT = 8;
    [&]<int... Is>(std::integer_sequence<int, Is...>) {
        (read_debug_register.template operator()<Is>(), ...);
    }(std::make_integer_sequence<int, DEBUG_REGISTER_COUNT>{});
}

// NOLINTNEXTLINE(readability-make-member-function-const)
void process::write_user_area(std::size_t offset, std::uint64_t data) {
    if (ptrace(PTRACE_POKEUSER, pid_, offset, data) == -1) {
        error::send_errno("PTRACE_POKEUSER failed");
    }
}

// NOLINTNEXTLINE(readability-make-member-function-const)
void process::write_gprs(const user_regs_struct &gprs) {
    if (ptrace(PTRACE_SETREGS, pid_, nullptr, &gprs) == -1) {
        error::send_errno("PTRACE_SETREGS failed");
    }
}

// NOLINTNEXTLINE(readability-make-member-function-const)
void process::write_fprs(const user_fpregs_struct &fprs) {
    if (ptrace(PTRACE_SETFPREGS, pid_, nullptr, &fprs) == -1) {
        error::send_errno("PTRACE_SETFPREGS failed");
    }
}

std::vector<std::byte> process::read_memory(virt_addr addr, std::size_t size) const {
    // Prepare data buffer and local iovec
    std::vector<std::byte> data(size);
    ::iovec local_iov = {.iov_base = data.data(), .iov_len = data.size()};

    // Allocate remote iovecs for each page
    std::vector<::iovec> remote_iovs;
    while (size > 0) {
        auto size_to_next_page_boundary = PAGE_SIZE - (addr.addr() & PAGE_MASK);
        auto iov_len = std::min(size, size_to_next_page_boundary);
        remote_iovs.emplace_back(
            ::iovec{.iov_base =
                        /* NOLINT(performance-no-int-to-ptr) */ reinterpret_cast<void *>(addr.addr()),
                    .iov_len = iov_len});

        addr += iov_len;
        size -= iov_len;
    }

    if (::process_vm_readv(pid_, &local_iov, 1, remote_iovs.data(), remote_iovs.size(), 0) == -1) {
        error::send_errno("process_vm_readv failed");
    }

    return data;
}

[[nodiscard]] std::vector<std::byte> process::read_memory_without_traps(virt_addr addr, std::size_t size) const {
    auto memory = read_memory(addr, size);
    for (const auto &bp : breakpoint_sites_.get_in_address_range(addr, addr + size)) {
        if (!bp->is_enabled() || bp->is_hardware()) {
            continue;
        }
        auto offset = bp->address() - addr;
        memory[offset] = bp->original_byte_;
    }
    return memory;
}

// NOLINTNEXTLINE(readability-make-member-function-const)
void process::write_memory(virt_addr addr, std::span<const std::byte> data) {
    // We use PTRACE_POKEDATA here because it can write to PROT_READ or
    // PROT_EXEC (i.e. not writable) memory. However, it can only write exactly
    // 8 bytes at a time.
    while (!data.empty()) {
        // Write one word at a time
        auto word_start = addr.align_to_word();
        auto offset = addr - word_start;  // Offset of addr within the word
        auto word_end = word_start + WORD_SIZE;

        auto end_addr = std::min(word_end, addr + data.size());
        auto size = end_addr - addr;  // size of the data to write in the word

        uint64_t word = 0;

        if (word_start < addr || end_addr < word_end) {
            // Read the original word
            errno = 0;
            word = static_cast<uint64_t>(::ptrace(PTRACE_PEEKDATA, pid_, word_start.addr(), nullptr));
            if (errno != 0) {
                error::send_errno("ptrace PEEKDATA failed");
            }
        }

        // Copy the data into the word to write
        std::memcpy(reinterpret_cast<char *>(&word) + offset, data.data(), size);

        if (::ptrace(PTRACE_POKEDATA, pid_, word_start.addr(), word) == -1) {
            error::send_errno("ptrace POKEDATA failed");
        }

        addr = end_addr;
        data = data.subspan(size);
    }
}

breakpoint_site &process::create_breakpoint_site(virt_addr address, bool hardware, bool internal) {
    if (breakpoint_sites_.contains_address(address)) {
        error::send("Breakpoint site already exists at address " + std::to_string(address.addr()));
    }
    auto bp_site = std::unique_ptr<breakpoint_site>(new breakpoint_site(*this, address, hardware, internal));
    return breakpoint_sites_.push(std::move(bp_site));
}

watchpoint &process::create_watchpoint(virt_addr addr, stoppoint_mode mode, std::size_t size) {
    if (watchpoints_.contains_address(addr)) {
        error::send("Watchpoint already exists at address " + std::to_string(addr.addr()));
    }
    auto wp = std::unique_ptr<watchpoint>(new watchpoint(*this, addr, mode, size));
    return watchpoints_.push(std::move(wp));
}

int process::set_hardware_stoppoint(virt_addr addr, stoppoint_mode mode, std::size_t size) {
    auto mode_flag = encode_hardware_stoppoint_mode(mode);
    auto size_flag = encode_hardware_stoppoint_size(size);

    auto &regs = get_registers();
    auto control = regs.read_by_id_as<std::uint64_t>(register_id::dr7);

    // Find a free slot for the stoppoint
    int slot = find_free_stoppoint_register(control);
    auto dr_id = static_cast<register_id>(static_cast<int>(register_id::dr0) + slot);

    // Calculate the control bits locations for the stoppoint
    constexpr auto DR7_MODE_BITS_OFFSET = 16;
    auto enable_bits_location = 2 * slot;
    auto mode_bits_location = DR7_MODE_BITS_OFFSET + (4 * slot);
    auto size_bits_location = mode_bits_location + 2;

    // Calculate the control bits for the stoppoint
    std::uint64_t mask =
        (0b11ULL << enable_bits_location) | (0b11ULL << mode_bits_location) | (0b11ULL << size_bits_location);
    std::uint64_t flag =
        (0b01ULL << enable_bits_location) | (mode_flag << mode_bits_location) | (size_flag << size_bits_location);

    // Set the control bits for the stoppoint
    control &= ~mask;
    control |= flag;

    // Write the address and control bits to the registers
    regs.write_by_id(dr_id, addr.addr());
    regs.write_by_id(register_id::dr7, control);

    return 0;
}

void process::clear_hardware_stoppoint(int hw_stoppoint_index) {
    auto &regs = get_registers();
    auto control = regs.read_by_id_as<std::uint64_t>(register_id::dr7);

    // Clear the stoppoint
    std::uint64_t clear_mask = (0b11ULL << (2 * hw_stoppoint_index));
    control &= ~clear_mask;
    regs.write_by_id(register_id::dr7, control);
}

}  // namespace xdb
