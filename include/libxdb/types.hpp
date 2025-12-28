#pragma once

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <format>
#include <ostream>

namespace xdb {

constexpr std::size_t BYTE64_SIZE = 8;
constexpr std::size_t BYTE128_SIZE = 16;
constexpr std::uint64_t WORD_ALIGNMENT_MASK = 0x7ULL;

using byte64 = std::array<std::byte, BYTE64_SIZE>;
using byte128 = std::array<std::byte, BYTE128_SIZE>;

class elf;
class virt_addr;

// Absolute offset from the start of the object file
class file_offset {
   public:
    explicit file_offset(const elf& obj, std::uint64_t offset) : elf_(&obj), offset_(offset) {}
    auto offset() const noexcept -> std::uint64_t { return offset_; }
    auto elf_file() const noexcept -> const elf* { return elf_; }

   private:
    const elf* elf_ = nullptr;
    std::uint64_t offset_;
};

// Virtual address specified in the ELF file
class file_addr {
   public:
    file_addr(const elf& elf, std::uint64_t addr) : elf_(&elf), addr_(addr) {}
    file_addr() = default;

    auto addr() const noexcept -> std::uint64_t { return addr_; }
    auto addr_mut() noexcept -> std::uint64_t& { return addr_; }
    auto elf_file() const noexcept -> const elf* { return elf_; }
    auto to_virt_addr() const -> std::optional<virt_addr>;

    auto operator+(std::uint64_t offset) const noexcept -> file_addr { return {*elf_, addr_ + offset}; }
    auto operator-(std::uint64_t offset) const noexcept -> file_addr { return {*elf_, addr_ - offset}; }
    auto operator-(const file_addr& other) const -> std::uint64_t {
        assert(elf_ == other.elf_);
        return addr_ - other.addr_;
    }

    auto operator+=(std::uint64_t offset) noexcept -> file_addr& { return addr_ += offset, *this; }
    auto operator-=(std::uint64_t offset) noexcept -> file_addr& { return addr_ -= offset, *this; }

    auto operator==(const file_addr& other) const noexcept -> bool {
        return addr_ == other.addr_ && elf_ == other.elf_;
    }
    auto operator<=>(const file_addr& other) const {
        assert(elf_ == other.elf_);
        return addr_ <=> other.addr_;
    }

    friend auto operator<<(std::ostream& os, const file_addr& fa) -> std::ostream& {
        return os << "file_addr { elf<" << fa.elf_ << ">, addr: " << std::format("{:#x}", fa.addr_) << " }";
    }

   private:
    const elf* elf_ = nullptr;
    std::uint64_t addr_ = 0;
};

// Actual virtual address in the running process
class virt_addr {
   public:
    explicit virt_addr(std::uint64_t addr) : addr_(addr) {}

    auto addr() const noexcept -> std::uint64_t { return addr_; }
    auto align_to_word() const noexcept -> virt_addr { return virt_addr(addr_ & ~WORD_ALIGNMENT_MASK); }
    auto to_file_addr(const elf& obj) const -> std::optional<file_addr>;

    auto operator+(std::uint64_t offset) const noexcept -> virt_addr { return virt_addr(addr_ + offset); }
    auto operator-(std::uint64_t offset) const noexcept -> virt_addr { return virt_addr(addr_ - offset); }
    auto operator-(const virt_addr& other) const noexcept -> std::uint64_t { return addr_ - other.addr_; }

    auto operator+=(std::uint64_t offset) noexcept -> virt_addr& { return addr_ += offset, *this; }
    auto operator-=(std::uint64_t offset) noexcept -> virt_addr& { return addr_ -= offset, *this; }

    auto operator==(const virt_addr& other) const noexcept -> bool = default;
    auto operator<=>(const virt_addr& other) const noexcept = default;

   private:
    std::uint64_t addr_;
};

inline auto to_string(const xdb::virt_addr& virt_addr) -> std::string { return std::format("{:#x}", virt_addr.addr()); }

enum class stoppoint_mode : std::uint8_t {
    execute,
    write,
    read_write,
};

}  // namespace xdb
