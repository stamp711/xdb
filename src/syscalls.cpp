#include <cstdint>
#include <libxdb/error.hpp>
#include <libxdb/syscalls.hpp>
#include <unordered_map>

namespace {

const std::unordered_map<std::string_view, std::uint64_t> g_syscall_name_map = {
#define DEFINE_SYSCALL(name, id) {#name, id},
#include "include/syscalls.def.hpp"
#undef DEFINE_SYSCALL
};

}  // namespace

namespace xdb {

auto syscall_id_to_name(std::uint64_t id) -> std::string_view {
    switch (id) {
#define DEFINE_SYSCALL(name, id) \
    case id:                     \
        return #name;
#include "include/syscalls.def.hpp"
#undef DEFINE_SYSCALL
        default:
            error::send("Unknown syscall id");
    }
}

auto syscall_name_to_id(std::string_view name) -> std::uint64_t {
    auto it = g_syscall_name_map.find(name);
    if (it == g_syscall_name_map.end()) {
        error::send("Unknown syscall name");
    }
    return it->second;
}

}  // namespace xdb
