#pragma once

#include <cstddef>
#include <cstring>
#include <libxdb/types.hpp>
#include <string_view>
#include <vector>

namespace xdb {

template <class T>
auto from_bytes(const std::byte* bytes) -> T {
    T value;
    std::memcpy(&value, bytes, sizeof(T));
    return value;
}

template <class T>
auto as_bytes(T& value) -> std::byte* {
    return reinterpret_cast<std::byte*>(&value);
}

template <class T>
auto as_bytes(const T& value) -> const std::byte* {
    return reinterpret_cast<const std::byte*>(&value);
}

template <class T>
auto to_byte128(const T& value) -> byte128 {
    byte128 res{};
    std::memcpy(res.data(), &value, sizeof(T));
    return res;
}

template <class T>
auto to_byte64(const T& value) -> byte64 {
    byte64 res{};
    std::memcpy(res.data(), &value, sizeof(T));
    return res;
}

inline auto to_string_view(const std::byte* bytes, size_t size) -> std::string_view {
    return {reinterpret_cast<const char*>(bytes), size};
}

inline auto to_string_view(const std::vector<std::byte>& bytes) -> std::string_view {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

}  // namespace xdb
