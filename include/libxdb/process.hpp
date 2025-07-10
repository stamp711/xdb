#pragma once

#include <sys/types.h>

#include <filesystem>
#include <libxdb/registers.hpp>
#include <memory>

namespace xdb {

enum class process_state { running, stopped, exited, terminated };

struct stop_reason {
    stop_reason(int wait_status);
    process_state state;
    std::uint8_t info;
};

class process {
   public:
    // -- process management --
    static std::unique_ptr<process> launch(
        std::filesystem::path path, bool debug = true,
        std::optional<int> stdout_replacement = std::nullopt);

    static std::unique_ptr<process> attach(pid_t pid);

    // -- process control --
    void resume();
    stop_reason wait_on_signal();
    pid_t pid() const { return pid_; }
    process_state state() const { return state_; }

    // -- registers --
    registers &get_registers() { return *registers_; }
    const registers &get_registers() const { return *registers_; }
    void write_user_area(std::size_t offset, std::uint64_t data);
    void write_gprs(const user_regs_struct &gprs);
    void write_fprs(const user_fpregs_struct &fprs);

    // -- forbid default construct and copy --
    process() = delete;
    process(const process &) = delete;
    process &operator=(const process &) = delete;

    ~process();

   private:
    process(pid_t pid, bool terminate_on_destruction, bool is_attached)
        : pid_(pid),
          terminate_on_destruction_(terminate_on_destruction),
          is_attached_(is_attached),
          registers_(new registers(this)) {}

    void read_all_registers();

    pid_t pid_ = 0;
    bool terminate_on_destruction_ = true;
    bool is_attached_ = true;
    process_state state_ = process_state::stopped;
    std::unique_ptr<registers> registers_;
};

}  // namespace xdb
