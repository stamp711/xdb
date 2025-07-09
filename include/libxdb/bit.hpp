#pragma once

#include <cstddef>
#include <cstring>
#include <libxdb/types.hpp>

namespace xdb {

template <class T>
T from_bytes(const std::byte* bytes) {
    T value;
    std::memcpy(&value, bytes, sizeof(T));
    return value;
}

template <class T>
std::byte* as_bytes(T& value) {
    return reinterpret_cast<std::byte*>(&value);
}

template <class T>
const std::byte* as_bytes(const T& value) {
    return reinterpret_cast<const std::byte*>(&value);
}

template <class T>
byte128 to_byte128(const T& value) {
    byte128 res{};
    std::memcpy(res.data(), &value, sizeof(T));
    return res;
}

template <class T>
byte64 to_byte64(const T& value) {
    byte64 res{};
    std::memcpy(res.data(), &value, sizeof(T));
    return res;
}

}  // namespace xdb
