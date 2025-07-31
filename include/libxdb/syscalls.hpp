#pragma once

#include <cstdint>
#include <string_view>

namespace xdb {

std::string_view syscall_id_to_name(std::uint64_t id);
std::uint64_t syscall_name_to_id(std::string_view name);

}  // namespace xdb
