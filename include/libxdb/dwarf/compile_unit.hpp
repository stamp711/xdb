#pragma once

#include <cstdint>
#include <libxdb/dwarf/die.hpp>
#include <libxdb/dwarf/types.hpp>
#include <memory>
#include <span>
#include <unordered_map>

namespace xdb {

class line_table;
class dwarf;

class compile_unit {
   public:
    compile_unit(dwarf& parent_dwarf, std::span<const std::byte> span, std::size_t abbrev_offset);

    auto dwarf_info() const -> const dwarf& { return *parent; }
    auto span() const -> std::span<const std::byte> { return span_; }
    auto abbrev_table() const -> const std::unordered_map<std::uint64_t, abbrev>&;

    auto lines() const -> const line_table& { return *line_table_; }

    auto root() const -> die;

   private:
    dwarf* parent;
    std::span<const std::byte> span_;
    std::size_t abbrev_offset_;
    std::unique_ptr<line_table> line_table_;
};

}  // namespace xdb
