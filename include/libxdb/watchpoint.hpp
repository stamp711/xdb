#pragma once

#include <cstdint>
#include <libxdb/types.hpp>

namespace xdb {

class process;

class watchpoint {
   public:
    watchpoint() = delete;
    watchpoint(const watchpoint&) = delete;
    watchpoint& operator=(const watchpoint&) = delete;
    watchpoint(watchpoint&&) = delete;
    watchpoint& operator=(watchpoint&&) = delete;
    ~watchpoint() = default;

    using id_type = std::int32_t;
    [[nodiscard]] id_type id() const { return id_; }

    void enable();
    void disable();

    [[nodiscard]] bool is_enabled() const { return is_enabled_; }
    [[nodiscard]] virt_addr address() const { return address_; }
    [[nodiscard]] stoppoint_mode mode() const { return mode_; }
    [[nodiscard]] std::size_t size() const { return size_; }

    [[nodiscard]] bool at_address(virt_addr addr) const {
        return address_ == addr;
    }
    [[nodiscard]] bool in_range(virt_addr low, virt_addr high) const {
        return address_ >= low && address_ < high;
    }

   private:
    friend process;
    watchpoint(process& proc, virt_addr address, stoppoint_mode mode,
               std::size_t size);

    id_type id_;
    process* process_;
    virt_addr address_;
    stoppoint_mode mode_;
    std::size_t size_;
    bool is_enabled_;

    int hardware_register_index_ = -1;
};

}  // namespace xdb
