#pragma once

#include <sys/types.h>

#include <array>
#include <filesystem>
#include <libxdb/bit.hpp>
#include <libxdb/breakpoint_site.hpp>
#include <libxdb/register_info.hpp>
#include <libxdb/registers.hpp>
#include <libxdb/stoppoint_collection.hpp>
#include <libxdb/types.hpp>
#include <libxdb/watchpoint.hpp>
#include <memory>
#include <optional>
#include <span>
#include <unordered_set>
#include <variant>
#include <vector>

namespace xdb {

enum class process_state : std::uint8_t { running, stopped, exited, terminated };

enum class trap_type : std::uint8_t { unknown, single_step, software_breakpoint, hardware_stoppoint, syscall };

struct syscall_information {
    std::uint64_t id;
    bool is_entry;
    std::optional<std::array<std::uint64_t, 6>> args;  // is_entry == true
    std::optional<int> ret;                            // is_entry == false
};

struct stop_reason {
    stop_reason(int wait_status);
    process_state state;
    std::uint8_t info;
    std::optional<trap_type> trap_reason;
    std::optional<syscall_information> syscall_info;
};

class syscall_catch_policy {
   public:
    enum catch_mode : uint8_t { none, some, all };

    static syscall_catch_policy catch_all() { return {catch_mode::all, {}}; };
    static syscall_catch_policy catch_none() { return {catch_mode::none, {}}; };
    static syscall_catch_policy catch_some(std::span<const std::uint64_t> syscalls) {
        return {catch_mode::some, syscalls};
    };

    [[nodiscard]] bool catches_none() const {
        return mode_ == catch_mode::none || (mode_ == catch_mode::some && to_catch_.empty());
    }

    [[nodiscard]] bool catches_syscall_id(std::uint64_t id) const {
        return mode_ == catch_mode::all || (mode_ == catch_mode::some && to_catch_.contains(id));
    }

    [[nodiscard]] catch_mode get_mode() const { return mode_; }
    [[nodiscard]] const std::unordered_set<std::uint64_t> &get_to_catch() const { return to_catch_; }

   private:
    syscall_catch_policy(catch_mode mode, std::span<const std::uint64_t> to_catch)
        : mode_(mode), to_catch_(to_catch.begin(), to_catch.end()) {}

    catch_mode mode_ = catch_mode::none;
    std::unordered_set<std::uint64_t> to_catch_;
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
    static std::unique_ptr<process> launch(const std::filesystem::path &path, bool debug = true,
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
        return virt_addr(get_registers().read_by_id_as<std::uint64_t>(register_id::rip));
    }
    void set_pc(virt_addr addr) { get_registers().write_by_id(register_id::rip, addr.addr()); }

    // -- memory read/write --
    [[nodiscard]] std::vector<std::byte> read_memory(virt_addr addr, std::size_t size) const;
    [[nodiscard]] std::vector<std::byte> read_memory_without_traps(virt_addr addr, std::size_t size) const;
    void write_memory(virt_addr addr, std::span<const std::byte> data);
    template <typename T>
    [[nodiscard]] T read_memory_as(virt_addr address) const {
        auto data = read_memory(address, sizeof(T));
        return from_bytes<T>(data.data());
    }

    // -- breakpoint sites --
    breakpoint_site &create_breakpoint_site(virt_addr addr, bool hardware = false, bool internal = false);
    [[nodiscard]] stoppoint_collection<breakpoint_site> &breakpoint_sites() { return breakpoint_sites_; }
    [[nodiscard]] const stoppoint_collection<breakpoint_site> &breakpoint_sites() const { return breakpoint_sites_; }

    // -- watchpoints --
    watchpoint &create_watchpoint(virt_addr addr, stoppoint_mode mode, std::size_t size);
    [[nodiscard]] stoppoint_collection<watchpoint> &watchpoints() { return watchpoints_; }
    [[nodiscard]] const stoppoint_collection<watchpoint> &watchpoints() const { return watchpoints_; }

    // If a hardware breakpoint or watchpoint is hit, this method returns the ID of the hit stoppoint.
    [[nodiscard]] std::variant<breakpoint_site::id_type, watchpoint::id_type> get_current_hardware_stoppoint() const;

    void set_syscall_catch_policy(syscall_catch_policy policy) { syscall_catch_policy_ = std::move(policy); }

   private:
    process(pid_t pid, bool terminate_on_destruction, bool is_attached)
        : pid_(pid),
          terminate_on_destruction_(terminate_on_destruction),
          is_attached_(is_attached),
          registers_(new registers(this)) {}

    void read_all_registers();

    // -- for friend classes - TODO: finer access control --
    friend class breakpoint_site, watchpoint;
    int set_hardware_stoppoint(virt_addr addr, stoppoint_mode mode, std::size_t size);
    void clear_hardware_stoppoint(int hw_stoppoint_index);

    // Populate optional fields related to SIGTRAP reason to stop_reason
    void augment_stop_reason(stop_reason &reason);

    pid_t pid_;
    bool terminate_on_destruction_;
    bool is_attached_;
    std::unique_ptr<registers> registers_;

    process_state state_ = process_state::stopped;

    stoppoint_collection<breakpoint_site> breakpoint_sites_ = {};
    stoppoint_collection<watchpoint> watchpoints_ = {};

    syscall_catch_policy syscall_catch_policy_ = syscall_catch_policy::catch_none();  // Defaults to catch_none
    bool expecting_syscall_exit_ = false;
};

}  // namespace xdb
