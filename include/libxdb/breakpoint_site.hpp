#pragma once

#include <cstdint>
#include <libxdb/types.hpp>

namespace xdb {

class process;

class breakpoint_site {
   public:
    breakpoint_site() = delete;
    breakpoint_site(const breakpoint_site&) = delete;
    auto operator=(const breakpoint_site&) -> breakpoint_site& = delete;
    breakpoint_site(breakpoint_site&&) = delete;
    auto operator=(breakpoint_site&&) -> breakpoint_site& = delete;
    ~breakpoint_site() = default;

    using id_type = std::int32_t;
    auto id() const -> id_type { return id_; }

    void enable();
    void disable();

    auto is_hardware() const -> bool { return is_hardware_; }
    auto is_internal() const -> bool { return is_internal_; }
    auto hardware_register_index() const -> int { return hardware_register_index_; }

    auto is_enabled() const -> bool { return is_enabled_; }
    auto address() const -> virt_addr { return address_; }

    auto at_address(virt_addr addr) const -> bool { return address_ == addr; }
    auto in_range(virt_addr low, virt_addr high) const -> bool { return address_ >= low && address_ < high; }

   private:
    friend process;
    breakpoint_site(process& proc, virt_addr address, bool is_hardware = false, bool is_internal = false);

    id_type id_;
    process* process_;
    virt_addr address_;
    bool is_enabled_;
    std::byte original_byte_;  // The original byte at the breakpoint address

    bool is_hardware_;
    bool is_internal_;
    int hardware_register_index_ = -1;
};

}  // namespace xdb
