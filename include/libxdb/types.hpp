#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>

namespace xdb {

constexpr std::size_t BYTE64_SIZE = 8;
constexpr std::size_t BYTE128_SIZE = 16;

using byte64 = std::array<std::byte, BYTE64_SIZE>;
using byte128 = std::array<std::byte, BYTE128_SIZE>;

class virt_addr {
   public:
    virt_addr() = default;
    explicit virt_addr(std::uint64_t addr) : addr_(addr) {}

    [[nodiscard]] std::uint64_t addr() const { return addr_; }

    [[nodiscard]] virt_addr align_to_word() const {
        constexpr std::uint64_t WORD_ALIGNMENT_MASK = 0x7ULL;
        return virt_addr(addr_ & ~WORD_ALIGNMENT_MASK);
    }

    [[nodiscard]] virt_addr operator+(std::uint64_t offset) const {
        return virt_addr(addr_ + offset);
    }

    [[nodiscard]] virt_addr operator-(std::uint64_t offset) const {
        return virt_addr(addr_ - offset);
    }

    [[nodiscard]] std::uint64_t operator-(const virt_addr& other) const {
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

    [[nodiscard]] bool operator==(const virt_addr& other) const = default;
    [[nodiscard]] auto operator<=>(const virt_addr& other) const = default;

   private:
    std::uint64_t addr_ = 0;
};

[[nodiscard]] inline std::string to_string(const xdb::virt_addr& virt_addr) {
    return std::format("{:#x}", virt_addr.addr());
}

enum class stoppoint_mode : std::uint8_t {
    execute,
    write,
    read_write,
};

}  // namespace xdb
