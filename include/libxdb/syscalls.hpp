#pragma once

#include <cstdint>
#include <string_view>

namespace xdb {

auto syscall_id_to_name(std::uint64_t id) -> std::string_view;
auto syscall_name_to_id(std::string_view name) -> std::uint64_t;

}  // namespace xdb
