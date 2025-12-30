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
#include <unordered_map>
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

    static auto catch_all() -> syscall_catch_policy { return {catch_mode::all, {}}; };
    static auto catch_none() -> syscall_catch_policy { return {catch_mode::none, {}}; };
    static auto catch_some(std::span<const std::uint64_t> syscalls) -> syscall_catch_policy {
        return {catch_mode::some, syscalls};
    };

    auto catches_none() const -> bool {
        return mode_ == catch_mode::none || (mode_ == catch_mode::some && to_catch_.empty());
    }

    auto catches_syscall_id(std::uint64_t id) const -> bool {
        return mode_ == catch_mode::all || (mode_ == catch_mode::some && to_catch_.contains(id));
    }

    auto get_mode() const -> catch_mode { return mode_; }
    auto get_to_catch() const -> const std::unordered_set<std::uint64_t>& { return to_catch_; }

   private:
    syscall_catch_policy(catch_mode mode, std::span<const std::uint64_t> to_catch)
        : mode_(mode), to_catch_(to_catch.begin(), to_catch.end()) {}

    catch_mode mode_ = catch_mode::none;
    std::unordered_set<std::uint64_t> to_catch_;
};

class target;  // fwd

class process {
   public:
    // -- forbid default construct and copy --
    process() = delete;
    process(const process&) = delete;
    process(process&&) = delete;
    auto operator=(const process&) -> process& = delete;
    auto operator=(process&&) -> process& = delete;

    ~process();

    // -- create by launching or attaching --
    static auto launch(const std::filesystem::path& path, bool debug = true,
                       std::optional<int> stdout_replacement = std::nullopt) -> std::unique_ptr<process>;
    static auto attach(pid_t pid) -> std::unique_ptr<process>;

    // -- process control --
    void resume();
    auto wait_on_signal() -> stop_reason;
    auto pid() const -> pid_t { return pid_; }
    auto state() const -> process_state { return state_; }
    auto step_instruction() -> xdb::stop_reason;

    // -- registers --
    auto get_registers() -> registers& { return *registers_; }
    auto get_registers() const -> const registers& { return *registers_; }
    void write_user_area(std::size_t offset, std::uint64_t data);
    void write_gprs(const user_regs_struct& gprs);
    void write_fprs(const user_fpregs_struct& fprs);
    auto get_pc() const -> virt_addr {
        return virt_addr(get_registers().read_by_id_as<std::uint64_t>(register_id::rip));
    }
    void set_pc(virt_addr addr) { get_registers().write_by_id(register_id::rip, addr.addr()); }

    // -- memory read/write --
    auto read_memory(virt_addr addr, std::size_t size) const -> std::vector<std::byte>;
    auto read_memory_without_traps(virt_addr addr, std::size_t size) const -> std::vector<std::byte>;
    void write_memory(virt_addr addr, std::span<const std::byte> data);
    template <typename T>
    auto read_memory_as(virt_addr address) const -> T {
        auto data = read_memory(address, sizeof(T));
        return from_bytes<T>(data.data());
    }

    // -- breakpoint sites --
    auto create_breakpoint_site(virt_addr addr, bool hardware = false, bool internal = false) -> breakpoint_site&;
    auto breakpoint_sites() -> stoppoint_collection<breakpoint_site>& { return breakpoint_sites_; }
    auto breakpoint_sites() const -> const stoppoint_collection<breakpoint_site>& { return breakpoint_sites_; }

    // -- watchpoints --
    auto create_watchpoint(virt_addr addr, stoppoint_mode mode, std::size_t size) -> watchpoint&;
    auto watchpoints() -> stoppoint_collection<watchpoint>& { return watchpoints_; }
    auto watchpoints() const -> const stoppoint_collection<watchpoint>& { return watchpoints_; }

    // If a hardware breakpoint or watchpoint is hit, this method returns the ID of the hit stoppoint.
    auto get_current_hardware_stoppoint() const -> std::variant<breakpoint_site::id_type, watchpoint::id_type>;

    void set_syscall_catch_policy(syscall_catch_policy policy) { syscall_catch_policy_ = std::move(policy); }

    auto get_auxv() const -> std::unordered_map<std::uint64_t, std::uint64_t>;

    void set_target(target& target) { target_ = &target; }

   private:
    process(pid_t pid, bool terminate_on_destruction, bool is_attached)
        : pid_(pid),
          terminate_on_destruction_(terminate_on_destruction),
          is_attached_(is_attached),
          registers_(new registers(this)) {}

    void read_all_registers_();

    // -- for friend classes - TODO: finer access control --
    friend class breakpoint_site, watchpoint;
    auto set_hardware_stoppoint_(virt_addr addr, stoppoint_mode mode, std::size_t size) -> int;
    void clear_hardware_stoppoint_(int hw_stoppoint_index);

    // Populate optional fields related to SIGTRAP reason to stop_reason
    void augment_stop_reason_(stop_reason& reason);

    pid_t pid_;
    bool terminate_on_destruction_;
    bool is_attached_;
    std::unique_ptr<registers> registers_;

    process_state state_ = process_state::stopped;

    stoppoint_collection<breakpoint_site> breakpoint_sites_ = {};
    stoppoint_collection<watchpoint> watchpoints_ = {};

    syscall_catch_policy syscall_catch_policy_ = syscall_catch_policy::catch_none();  // Defaults to catch_none
    bool expecting_syscall_exit_ = false;

    target* target_ = nullptr;
};

}  // namespace xdb
