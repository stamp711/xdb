#include <array>
#include <charconv>
#include <cstdint>
#include <libxdb/error.hpp>
#include <optional>
#include <string_view>
#include <vector>

namespace xdb {

template <class T>
std::optional<T> to_integral(std::string_view sv, int base = 10) {
    auto begin = sv.begin();
    if (base == 16 && sv.size() >= 2 && begin[0] == '0' && begin[1] == 'x') {
        begin += 2;  // Skip "0x" prefix for hexadecimal
    }

    T res;
    auto from_chars_res = std::from_chars(begin, sv.end(), res, base);

    if (from_chars_res.ptr != sv.end()) {
        // Conversion did not consume the entire string
        return std::nullopt;
    } else {
        return res;
    }
}

template <>
inline std::optional<std::byte> to_integral(std::string_view sv, int base) {
    return to_integral<std::uint8_t>(sv, base).transform(
        [](auto i) { return static_cast<std::byte>(i); });
}

template <class T>
std::optional<T> to_float(std::string_view sv) {
    T res;
    auto from_chars_res = std::from_chars(sv.begin(), sv.end(), res);

    if (from_chars_res.ptr != sv.end()) {
        // Conversion did not consume the entire string
        return std::nullopt;
    } else {
        return res;
    }
}

template <std::size_t N>
auto parse_vector(std::string_view sv) {
    auto err = [] { error::send("Invalid vector value format"); };
    std::array<std::byte, N> bytes;

    if (sv.size() !=
        (/* brackets */ 2) + (/* each byte */ N * 4) + (/* commas */ N - 1)) {
        err();
    }

    const char* c = sv.data();
    if (*c++ != '[') err();
    for (size_t i = 0; i < N - 1; ++i) {
        auto b = to_integral<std::byte>({c, 4}, 16);
        if (!b) err();
        bytes[i] = *b;
        c += 4;
        if (*c++ != ',') err();
    }
    auto b = to_integral<std::byte>({c, 4}, 16);
    if (!b) err();
    bytes[N - 1] = *b;
    c += 4;
    if (*c++ != ']') err();

    return bytes;
}

// Dynamic version for variable-length byte arrays
inline std::vector<std::byte> parse_vector(std::string_view sv) {
    auto err = [] { error::send("Invalid vector value format"); };
    std::vector<std::byte> bytes;

    if (sv.size() < 2 || sv[0] != '[' || sv.back() != ']') {
        err();
    }

    std::string_view content = sv.substr(1, sv.size() - 2);
    if (content.empty()) {
        return bytes;  // Empty array is valid
    }

    const char* c = content.data();
    const char* end = content.data() + content.size();

    while (c < end) {
        // Skip whitespace
        while (c < end && (*c == ' ' || *c == '\t')) ++c;
        if (c >= end) break;

        // Parse hex byte
        if (c + 4 > end || c[0] != '0' || c[1] != 'x') {
            err();
        }

        auto b = to_integral<std::byte>({c, 4}, 16);
        if (!b) err();
        bytes.push_back(*b);
        c += 4;

        // Skip whitespace
        while (c < end && (*c == ' ' || *c == '\t')) ++c;

        // Check for comma or end
        if (c < end) {
            if (*c != ',') err();
            ++c;
        }
    }

    return bytes;
}

}  // namespace xdb
