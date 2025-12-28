#pragma once

#include <cstdint>
#include <libxdb/bit.hpp>
#include <span>
#include <string_view>

namespace xdb {

class cursor {
   public:
    explicit cursor(std::span<const std::byte> span) : span_(span) {}

    auto data() const noexcept -> const std::byte* { return span_.data(); }

    auto operator++() -> cursor& { return span_ = span_.subspan(1), *this; }
    auto operator+=(std::size_t offset) -> cursor& { return span_ = span_.subspan(offset), *this; }

    auto finished() const noexcept -> bool { return span_.empty(); }

    template <class T>
    auto get_fixed_int() -> T {
        auto t = xdb::from_bytes<T>(span_.data());
        *this += sizeof(T);
        return t;
    }

    auto get_u8() -> std::uint8_t { return get_fixed_int<std::uint8_t>(); }
    auto get_u16() -> std::uint16_t { return get_fixed_int<std::uint16_t>(); }
    auto get_u32() -> std::uint32_t { return get_fixed_int<std::uint32_t>(); }
    auto get_u64() -> std::uint64_t { return get_fixed_int<std::uint64_t>(); }
    auto get_i8() -> std::int8_t { return get_fixed_int<std::int8_t>(); }
    auto get_i16() -> std::int16_t { return get_fixed_int<std::int16_t>(); }
    auto get_i32() -> std::int32_t { return get_fixed_int<std::int32_t>(); }
    auto get_i64() -> std::int64_t { return get_fixed_int<std::int64_t>(); }

    auto get_string() -> std::string_view {
        auto null_terminator = std::ranges::find(span_, std::byte{0});
        auto strlen = static_cast<std::size_t>(null_terminator - span_.begin());
        std::string_view ret(reinterpret_cast<const char*>(span_.data()), strlen);
        *this += (strlen + 1);
        return ret;
    }

    auto get_uleb128() -> std::uint64_t {
        std::uint64_t res = 0;
        std::size_t shift = 0;
        std::uint8_t byte = 0;
        while (true) {
            byte = get_u8();
            res |= static_cast<std::uint64_t>(byte & 0x7F) << shift;
            shift += 7;
            if ((byte & 0x80) == 0) break;
        }
        return res;
    }

    auto get_sleb128() -> std::int64_t {
        std::uint64_t res = 0;  // use uint because left shifting negative int is UB
        std::size_t shift = 0;
        std::uint8_t byte = 0;
        while (true) {
            byte = get_u8();
            res |= static_cast<std::uint64_t>(byte & 0x7F) << shift;
            shift += 7;
            if ((byte & 0x80) == 0) break;
        }
        // Do sign extension
        if (shift < sizeof(res) * 8 && (byte & 0x40) != 0) {
            res |= (~std::uint64_t{0} << shift);  // shift has been checked to avoid UB
        }
        return static_cast<std::int64_t>(res);
    }

    void skip_form(uint64_t form);

   private:
    std::span<const std::byte> span_;
};

}  // namespace xdb
