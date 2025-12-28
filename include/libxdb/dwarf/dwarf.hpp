#pragma once

#include <cstdint>
#include <libxdb/dwarf/compile_unit.hpp>
#include <libxdb/dwarf/die.hpp>
#include <libxdb/dwarf/line_table.hpp>
#include <libxdb/dwarf/types.hpp>
#include <memory>
#include <span>
#include <unordered_map>
#include <vector>

namespace xdb {
class elf;

class dwarf {
   public:
    dwarf(const elf& parent_elf);

    ~dwarf() = default;
    dwarf(const dwarf&) = delete;
    dwarf(dwarf&&) = delete;

    auto operator=(const dwarf&) -> dwarf& = delete;
    auto operator=(dwarf&&) -> dwarf& = delete;

    auto elf_file() const -> const elf& { return *elf_; }
    auto debug_info() const -> std::span<const std::byte> { return debug_info_span_; }
    auto get_abbrev_table(std::size_t byte_offset) -> const std::unordered_map<std::uint64_t, abbrev>&;
    auto compile_units() const -> const std::vector<std::unique_ptr<compile_unit>>& { return compile_units_; }

    auto compile_unit_containing_address(file_addr address) const -> const compile_unit*;
    auto function_containing_address(file_addr address) const -> std::optional<die>;  // Be aware of lifetimes!
    auto find_functions(const std::string& name) const -> std::vector<die>;           // Be aware of lifetimes!

    auto line_entry_at_address(file_addr address) const -> line_table::iterator {
        const auto* cu = this->compile_unit_containing_address(address);
        if (cu == nullptr) return cu->line_table().end();
        return cu->line_table().get_entry_by_address(address);
    }

   private:
    const elf* elf_;
    std::span<const std::byte> debug_info_span_;
    std::unordered_map<std::size_t, std::unique_ptr<const std::unordered_map<std::uint64_t, abbrev>>>
        abbrev_table_cache_;
    std::vector<std::unique_ptr<compile_unit>> compile_units_;

    mutable std::unordered_multimap<std::string, const die> function_index_;

    auto index_() const -> void;  // index all DIEs
    auto index_die_(const die& die) const -> void;
};

}  // namespace xdb
