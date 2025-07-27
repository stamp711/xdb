#pragma once

#include <sys/types.h>

#include <filesystem>
#include <libxdb/bit.hpp>
#include <libxdb/breakpoint_site.hpp>
#include <libxdb/register_info.hpp>
#include <libxdb/registers.hpp>
#include <libxdb/stoppoint_collection.hpp>
#include <libxdb/types.hpp>
#include <memory>
#include <span>

namespace xdb {

enum class process_state : std::uint8_t {
    running,
    stopped,
    exited,
    terminated
};

struct stop_reason {
    stop_reason(int wait_status);
    process_state state;
    std::uint8_t info;
};

class process {
   public:
    // -- forbid default construct and copy --
    process() = delete;
    process(const process &) = delete;
    process &operator=(const process &) = delete;
    process(process &&) = delete;
    process &operator=(process &&) = delete;

    ~process();

    // -- create by launching or attaching --
    static std::unique_ptr<process> launch(
        const std::filesystem::path &path, bool debug = true,
        std::optional<int> stdout_replacement = std::nullopt);
    static std::unique_ptr<process> attach(pid_t pid);

    // -- process control --
    void resume();
    stop_reason wait_on_signal();
    [[nodiscard]] pid_t pid() const { return pid_; }
    [[nodiscard]] process_state state() const { return state_; }
    xdb::stop_reason step_instruction();

    // -- registers --
    [[nodiscard]] registers &get_registers() { return *registers_; }
    [[nodiscard]] const registers &get_registers() const { return *registers_; }
    void write_user_area(std::size_t offset, std::uint64_t data);
    void write_gprs(const user_regs_struct &gprs);
    void write_fprs(const user_fpregs_struct &fprs);
    [[nodiscard]] virt_addr get_pc() const {
        return virt_addr(
            get_registers().read_by_id_as<std::uint64_t>(register_id::rip));
    }
    void set_pc(virt_addr addr) {
        get_registers().write_by_id(register_id::rip, addr.addr());
    }

    // -- memory read/write --
    [[nodiscard]] std::vector<std::byte> read_memory(virt_addr addr,
                                                     std::size_t size) const;
    [[nodiscard]] std::vector<std::byte> read_memory_without_traps(
        virt_addr addr, std::size_t size) const;
    void write_memory(virt_addr addr, std::span<const std::byte> data);
    template <typename T>
    [[nodiscard]] T read_memory_as(virt_addr address) const {
        auto data = read_memory(address, sizeof(T));
        return from_bytes<T>(data.data());
    }

    // -- breakpoint sites --
    breakpoint_site &create_breakpoint_site(virt_addr addr);
    [[nodiscard]] stoppoint_collection<breakpoint_site> &breakpoint_sites() {
        return breakpoint_sites_;
    }
    [[nodiscard]] const stoppoint_collection<breakpoint_site> &
    breakpoint_sites() const {
        return breakpoint_sites_;
    }

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

    stoppoint_collection<breakpoint_site> breakpoint_sites_;
};

}  // namespace xdb
