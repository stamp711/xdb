#pragma once

#include <sys/user.h>

#include <algorithm>
#include <cstdint>
#include <libxdb/error.hpp>
#include <string_view>

namespace xdb {

enum class register_id {
#define DEFINE_REGISTER(name, dwarf_id, size, offset, type, format) name
#include <libxdb/detail/registers.inc>
#undef DEFINE_REGISTER
};

enum class register_type {
    gpr,      // General Purpose Register (e.g., rax)
    sub_gpr,  // Sub General Purpose Register (e.g., eax)
    fpr,      // Floating Point Register
    dr,       // Debug Register
};

enum class register_format { uint, double_float, long_double, vector };

struct register_info {
    register_id id;
    std::string_view name;
    int32_t dwarf_id;
    size_t size;
    size_t offset;
    register_type type;
    register_format format;
};

inline constexpr const register_info g_register_infos[] = {
#define DEFINE_REGISTER(name, dwarf_id, size, offset, type, format) \
    {register_id::name, #name, dwarf_id, size, offset, type, format}
#include <libxdb/detail/registers.inc>
#undef DEFINE_REGISTER

};

template <class F>
const register_info& register_info_by(F f) {
    auto it = std::find_if(std::begin(g_register_infos),
                           std::end(g_register_infos), f);
    if (it == std::end(g_register_infos)) {
        error::send("Could not find register info");
    }
    return *it;
}

inline const register_info& register_info_by_id(register_id id) {
    return register_info_by(
        [id](const register_info& info) { return info.id == id; });
}

inline const register_info& register_info_by_name(std::string_view name) {
    return register_info_by(
        [name](const register_info& info) { return info.name == name; });
}

inline const register_info& register_info_by_dwarf_id(int32_t dwarf_id) {
    return register_info_by([dwarf_id](const register_info& info) {
        return info.dwarf_id == dwarf_id;
    });
}

}  // namespace xdb