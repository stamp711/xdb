#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>

namespace xdb {

using byte64 = std::array<std::byte, 8>;
using byte128 = std::array<std::byte, 16>;

class virt_addr {
   public:
    virt_addr() = default;
    explicit virt_addr(std::uint64_t addr) : addr_(addr) {}

    std::uint64_t addr() const { return addr_; }

    virt_addr align_to_word() const { return virt_addr(addr_ & ~0x7ull); }

    virt_addr operator+(std::uint64_t offset) const {
        return virt_addr(addr_ + offset);
    }

    virt_addr operator-(std::uint64_t offset) const {
        return virt_addr(addr_ - offset);
    }

    std::uint64_t operator-(const virt_addr& other) const {
        return addr_ - other.addr_;
    }

    virt_addr& operator+=(std::uint64_t offset) {
        addr_ += offset;
        return *this;
    }

    virt_addr& operator-=(std::uint64_t offset) {
        addr_ -= offset;
        return *this;
    }

    bool operator==(const virt_addr& other) const = default;
    auto operator<=>(const virt_addr& other) const = default;

   private:
    std::uint64_t addr_ = 0;
};

inline std::string to_string(const xdb::virt_addr& va) {
    return std::format("{:#x}", va.addr());
}

}  // namespace xdb
