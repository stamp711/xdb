/// @file types.hpp
/// @brief Core address types for the debugger.
///
/// ## Address Spaces
///
/// The debugger deals with multiple address spaces:
///
/// ```
///                     Debuggee Process
///                     ┌─────────────────────────┐
///    virt_addr ──────►│  Running program memory │
///                     │  (ptrace read/write)    │
///                     └─────────────────────────┘
///                               ▲
///                               │ + load_bias
///                               │
///                     ┌─────────────────────────┐
///    file_addr ──────►│  ELF virtual addresses  │
///                     │  (sh_addr, st_value)    │
///                     └─────────────────────────┘
///
///                     ┌─────────────────────────┐
///    file_offset ────►│  Offset in ELF file     │
///                     │  (sh_offset)            │
///                     └─────────────────────────┘
///                               │
///                               │ + elf::data_
///                               ▼
///                     ┌─────────────────────────┐
///    std::byte* ─────►│  Debugger's mmap'd ELF  │
///                     └─────────────────────────┘
/// ```
///
/// - `virt_addr`: Runtime address in debuggee. Not tied to any ELF.
/// - `file_addr`: Static address from ELF. Tied to a specific ELF.
/// - `file_offset`: Byte offset in ELF file. Tied to a specific ELF.
/// - `std::byte*`: Raw pointer in debugger's address space (mmapped ELF data).

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

/// Byte offset from the start of an (mmaped) ELF file.
///
/// Used for navigating ELF file structure (e.g., sh_offset in section headers).
/// Associated with a specific ELF file and can be converted to a pointer into
/// the debugger's mmapped ELF data via as_data_pointer().
///
/// @note This is NOT an address - it's an offset within the ELF file on disk.
class file_offset {
   public:
    explicit file_offset(const elf& obj, std::uint64_t offset) : elf_(&obj), offset_(offset) {}
    auto offset() const noexcept -> std::uint64_t { return offset_; }
    auto elf_file() const noexcept -> const elf* { return elf_; }

    auto operator+(std::uint64_t offset) const noexcept -> file_offset { return file_offset{*elf_, offset_ + offset}; }
    auto operator-(std::uint64_t offset) const noexcept -> file_offset { return file_offset{*elf_, offset_ - offset}; }

    /// Convert to a data pointer within the mmaped elf file.
    /// @return Pointer to the byte at this offset in the debugger's mmapped ELF data.
    auto as_data_pointer() const -> const std::byte*;

   private:
    const elf* elf_ = nullptr;
    std::uint64_t offset_;
};

/// Virtual address as specified in an ELF file (pre-relocation).
///
/// Represents addresses found in ELF metadata: symbol values (st_value),
/// section virtual addresses (sh_addr), DWARF debug info, etc.
/// Associated with a specific ELF file. To get the runtime address in the
/// debuggee process, convert to virt_addr by adding the load bias.
///
/// @see virt_addr for runtime addresses in the debuggee process.
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

/// Virtual address in the debuggee process's address space.
///
/// Represents runtime addresses where code/data actually lives in the
/// running process. Used for ptrace operations, breakpoints, watchpoints, etc.
/// Not tied to any specific ELF - a process may have multiple loaded ELFs.
/// To convert to file_addr, the target ELF must be specified.
///
/// @see file_addr for static addresses from ELF files.
class virt_addr {
   public:
    explicit virt_addr(std::uint64_t addr) : addr_(addr) {}

    auto addr() const noexcept -> std::uint64_t { return addr_; }
    auto align_to_word() const noexcept -> virt_addr { return virt_addr(addr_ & ~WORD_ALIGNMENT_MASK); }

    /// Converts a virtual address to a file address within the given ELF object.
    ///
    /// @param obj The ELF object to use for conversion.
    /// @return The file address corresponding to the virtual address. If the virtual address is not within the ELF
    ///         object's address space, returns nullopt;
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
