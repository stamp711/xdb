#pragma once

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <format>

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
    [[nodiscard]] std::uint64_t offset() const noexcept { return offset_; }
    [[nodiscard]] const elf* elf_file() const noexcept { return elf_; }

   private:
    const elf* elf_ = nullptr;
    std::uint64_t offset_;
};

// Virtual address specified in the ELF file
class file_addr {
   public:
    explicit file_addr(const elf& elf, std::uint64_t addr) : elf_(&elf), addr_(addr) {}

    [[nodiscard]] std::uint64_t addr() const noexcept { return addr_; }
    [[nodiscard]] const elf* elf_file() const noexcept { return elf_; }
    [[nodiscard]] std::optional<virt_addr> to_virt_addr() const;

    [[nodiscard]] file_addr operator+(std::uint64_t offset) const noexcept { return file_addr(*elf_, addr_ + offset); }
    [[nodiscard]] file_addr operator-(std::uint64_t offset) const noexcept { return file_addr(*elf_, addr_ - offset); }
    [[nodiscard]] std::uint64_t operator-(const file_addr& other) const {
        assert(elf_ == other.elf_);
        return addr_ - other.addr_;
    }

    file_addr& operator+=(std::uint64_t offset) noexcept { return addr_ += offset, *this; }
    file_addr& operator-=(std::uint64_t offset) noexcept { return addr_ -= offset, *this; }

    [[nodiscard]] bool operator==(const file_addr& other) const noexcept {
        return addr_ == other.addr_ && elf_ == other.elf_;
    }
    [[nodiscard]] auto operator<=>(const file_addr& other) const {
        assert(elf_ == other.elf_);
        return addr_ <=> other.addr_;
    }

   private:
    const elf* elf_ = nullptr;
    std::uint64_t addr_;
};

// Actual virtual address in the running process
class virt_addr {
   public:
    explicit virt_addr(std::uint64_t addr) : addr_(addr) {}

    [[nodiscard]] std::uint64_t addr() const noexcept { return addr_; }
    [[nodiscard]] virt_addr align_to_word() const noexcept { return virt_addr(addr_ & ~WORD_ALIGNMENT_MASK); }
    [[nodiscard]] std::optional<file_addr> to_file_addr(const elf& obj) const;

    [[nodiscard]] virt_addr operator+(std::uint64_t offset) const noexcept { return virt_addr(addr_ + offset); }
    [[nodiscard]] virt_addr operator-(std::uint64_t offset) const noexcept { return virt_addr(addr_ - offset); }
    [[nodiscard]] std::uint64_t operator-(const virt_addr& other) const noexcept { return addr_ - other.addr_; }

    virt_addr& operator+=(std::uint64_t offset) noexcept { return addr_ += offset, *this; }
    virt_addr& operator-=(std::uint64_t offset) noexcept { return addr_ -= offset, *this; }

    [[nodiscard]] bool operator==(const virt_addr& other) const noexcept = default;
    [[nodiscard]] auto operator<=>(const virt_addr& other) const noexcept = default;

   private:
    std::uint64_t addr_;
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
