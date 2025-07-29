#include <array>
#include <charconv>
#include <cstdint>
#include <libxdb/error.hpp>
#include <optional>
#include <string_view>
#include <vector>

namespace xdb {

namespace {
constexpr int DECIMAL_BASE = 10;
constexpr int HEX_BASE = 16;
constexpr std::size_t HEX_BYTE_LENGTH = 4;  // "0x??" format
}  // namespace

template <class T>
[[nodiscard]] std::optional<T> to_integral(std::string_view sv, int base = DECIMAL_BASE) {
    const auto* begin = sv.begin();
    if (base == HEX_BASE && sv.size() >= 2 && begin[0] == '0' && begin[1] == 'x') {
        begin += 2;  // Skip "0x" prefix for hexadecimal
    }

    T res;
    auto from_chars_res = std::from_chars(begin, sv.end(), res, base);

    if (from_chars_res.ptr != sv.end()) {
        // Conversion did not consume the entire string
        return std::nullopt;
    }

    return res;
}

template <>
[[nodiscard]] inline std::optional<std::byte> to_integral(std::string_view sv, int base) {
    return to_integral<std::uint8_t>(sv, base).transform([](auto i) { return static_cast<std::byte>(i); });
}

template <class T>
[[nodiscard]] std::optional<T> to_float(std::string_view sv) {
    T res;
    auto from_chars_res = std::from_chars(sv.begin(), sv.end(), res);

    if (from_chars_res.ptr != sv.end()) {
        // Conversion did not consume the entire string
        return std::nullopt;
    }

    return res;
}

template <std::size_t N>
[[nodiscard]] auto parse_vector(std::string_view sv) {
    auto err = [] { error::send("Invalid vector value format"); };
    std::array<std::byte, N> bytes;

    if (sv.size() != (/* brackets */ 2) + (/* each byte */ N * HEX_BYTE_LENGTH) + (/* commas */ N - 1)) {
        err();
    }

    const char* c = sv.data();
    if (*c++ != '[') err();
    for (size_t i = 0; i < N - 1; ++i) {
        auto b = to_integral<std::byte>({c, HEX_BYTE_LENGTH}, HEX_BASE);
        if (!b) err();
        bytes[i] = *b;
        c += HEX_BYTE_LENGTH;
        if (*c++ != ',') err();
    }
    auto b = to_integral<std::byte>({c, HEX_BYTE_LENGTH}, HEX_BASE);
    if (!b) err();
    bytes[N - 1] = *b;
    c += HEX_BYTE_LENGTH;
    if (*c++ != ']') err();

    return bytes;
}

// Dynamic version for variable-length byte arrays
[[nodiscard]] inline std::vector<std::byte> parse_vector(std::string_view sv) {
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
        if (c + HEX_BYTE_LENGTH > end || c[0] != '0' || c[1] != 'x') {
            err();
        }

        auto b = to_integral<std::byte>({c, HEX_BYTE_LENGTH}, HEX_BASE);
        if (!b) err();
        bytes.push_back(*b);
        c += HEX_BYTE_LENGTH;

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
