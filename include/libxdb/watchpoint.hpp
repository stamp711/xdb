#pragma once

#include <cstdint>
#include <libxdb/types.hpp>

namespace xdb {

class process;

class watchpoint {
   public:
    watchpoint() = delete;
    watchpoint(const watchpoint&) = delete;
    watchpoint(watchpoint&&) = delete;
    auto operator=(const watchpoint&) -> watchpoint& = delete;
    auto operator=(watchpoint&&) -> watchpoint& = delete;
    ~watchpoint() = default;

    using id_type = std::int32_t;
    auto id() const -> id_type { return id_; }

    void enable();
    void disable();

    auto is_enabled() const -> bool { return is_enabled_; }
    auto address() const -> virt_addr { return address_; }
    auto mode() const -> stoppoint_mode { return mode_; }
    auto size() const -> std::size_t { return size_; }

    auto data() const -> std::uint64_t { return data_; }
    auto previous_data() const -> std::uint64_t { return previous_data_; }

    auto at_address(virt_addr addr) const -> bool { return address_ == addr; }
    auto in_range(virt_addr low, virt_addr high) const -> bool { return address_ >= low && address_ < high; }

    void record_data_change();

   private:
    friend process;
    watchpoint(process& proc, virt_addr address, stoppoint_mode mode, std::size_t size);

    id_type id_;
    process* process_;
    virt_addr address_;
    stoppoint_mode mode_;
    std::size_t size_;
    bool is_enabled_;

    int hardware_register_index_ = -1;
    std::uint64_t data_ = 0;
    std::uint64_t previous_data_ = 0;
};

}  // namespace xdb
