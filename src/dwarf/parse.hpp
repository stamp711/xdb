#pragma once

#include <cstddef>
#include <cstdint>
#include <libxdb/dwarf/cursor.hpp>
#include <libxdb/dwarf/die.hpp>
#include <string_view>

namespace xdb::detail {

auto parse_die(const compile_unit& cu, cursor cur) -> die;

// DWARF 5 indirect-table resolvers.
auto resolve_addrx(const compile_unit& cu, std::size_t index) -> std::uint64_t;
auto resolve_strx(const compile_unit& cu, std::size_t index) -> std::string_view;

}  // namespace xdb::detail
