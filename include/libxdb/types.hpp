#pragma once

#include <array>
#include <cstddef>

namespace xdb {

using byte64 = std::array<std::byte, 8>;
using byte128 = std::array<std::byte, 16>;

}  // namespace xdb