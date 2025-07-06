#pragma once

#include <sys/types.h>

#include <filesystem>

namespace xdb {

enum class process_state { running, stopped, exited, terminated };

struct stop_reason {
    stop_reason(int wait_status);
    process_state state;
    std::uint8_t info;
};

class process {
   public:
    static std::unique_ptr<process> launch(std::filesystem::path path,
                                           bool debug = true);
    static std::unique_ptr<process> attach(pid_t pid);

    void resume();
    stop_reason wait_on_signal();
    pid_t pid() const { return pid_; }
    process_state state() const { return state_; }

    process() = delete;
    process(const process &) = delete;
    process &operator=(const process &) = delete;

    ~process();

   private:
    process(pid_t pid, bool terminate_on_destruction, bool is_attached)
        : pid_(pid),
          terminate_on_destruction_(terminate_on_destruction),
          is_attached_(is_attached) {}

    pid_t pid_ = 0;
    bool terminate_on_destruction_ = true;
    bool is_attached_ = true;
    process_state state_ = process_state::stopped;
};

}  // namespace xdb
