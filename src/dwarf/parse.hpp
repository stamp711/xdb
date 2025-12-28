#pragma once

#include <libxdb/dwarf/cursor.hpp>
#include <libxdb/dwarf/die.hpp>

namespace xdb::detail {
auto parse_die(const compile_unit& cu, cursor cur) -> die;
}
