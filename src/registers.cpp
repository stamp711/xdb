#include <sys/ptrace.h>

#include <cstring>
#include <libxdb/bit.hpp>
#include <libxdb/process.hpp>
#include <libxdb/register_info.hpp>
#include <libxdb/registers.hpp>
#include <libxdb/types.hpp>
#include <span>
#include <type_traits>
#include <utility>
#include <variant>

namespace {
constexpr std::uint64_t ALIGNMENT_MASK = 0b111ULL;
}  // namespace

xdb::registers::value xdb::registers::read(const register_info& info) const {
    auto user_bytes_span = std::span{as_bytes(data_), sizeof(data_)};
    const auto* byte_ptr = &user_bytes_span.at(info.offset);

    switch (info.format) {
        case register_format::uint:
            switch (info.size) {
                case sizeof(std::uint8_t):
                    return from_bytes<std::uint8_t>(byte_ptr);
                case sizeof(std::uint16_t):
                    return from_bytes<std::uint16_t>(byte_ptr);
                case sizeof(std::uint32_t):
                    return from_bytes<std::uint32_t>(byte_ptr);
                case sizeof(std::uint64_t):
                    return from_bytes<std::uint64_t>(byte_ptr);
                default:
                    error::send("Unexpected size for uint register format: " +
                                std::to_string(info.size));
            }

        case register_format::double_float:
            return from_bytes<double>(byte_ptr);

        case register_format::long_double:
            return from_bytes<long double>(byte_ptr);

        case register_format::vector:
            switch (info.size) {
                case sizeof(byte64):
                    return from_bytes<byte64>(byte_ptr);
                case sizeof(byte128):
                    return from_bytes<byte128>(byte_ptr);
                default:
                    error::send("Unexpected size for vector register format: " +
                                std::to_string(info.size));
            }

        default:
            std::unreachable();
    }
}

namespace {
template <class T>
xdb::byte128 widen(const xdb::register_info& info, T t) {
    if constexpr (std::is_floating_point_v<T>) {
        // Floating point
        if (info.format == xdb::register_format::double_float) {
            return xdb::to_byte128(static_cast<double>(t));
        }
        if (info.format == xdb::register_format::long_double) {
            return xdb::to_byte128(static_cast<long double>(t));
        }
    } else if constexpr (std::is_signed_v<T>) {
        // Signed integer, do sign extension
        if (info.format == xdb::register_format::uint) {
            switch (info.size) {
                case sizeof(std::uint8_t):
                    return xdb::to_byte128(static_cast<std::uint8_t>(t));
                case sizeof(std::uint16_t):
                    return xdb::to_byte128(static_cast<std::uint16_t>(t));
                case sizeof(std::uint32_t):
                    return xdb::to_byte128(static_cast<std::uint32_t>(t));
                case sizeof(std::uint64_t):
                    return xdb::to_byte128(static_cast<std::uint64_t>(t));
                default:
                    xdb::error::send(
                        "Unexpected size for uint register format: " +
                        std::to_string(info.size));
            }
        }
    }

    return xdb::to_byte128(t);
}
}  // namespace

void xdb::registers::write(const register_info& info, value val) {
    auto user_bytes_span = std::span{as_bytes(data_), sizeof(data_)};

    // Write val to user_bytes
    std::visit(
        [&info, &user_bytes_span](auto& v) {
            if (sizeof(v) <= info.size) {
                auto wide = widen(info, v);
                auto val_bytes = as_bytes(wide);
                std::memcpy(&user_bytes_span.at(info.offset), val_bytes,
                            info.size);
            } else {
                error::send(
                    "Unexpected size for value in write operation: val size " +
                    std::to_string(sizeof(v)) + " vs register size " +
                    std::to_string(info.size));
            }
        },
        val);

    // Write to the process's user area
    if (info.type == register_type::fpr) {
        // PTRACE_POKEUSER does not support writing to the i387 area directly,
        // so we write all FPRs at once.
        proc_->write_fprs(data_.i387);
    } else {
        auto aligned_offset =
            info.offset & ~ALIGNMENT_MASK;  // Align to 8 bytes
        proc_->write_user_area(
            aligned_offset,
            from_bytes<std::uint64_t>(&user_bytes_span.at(aligned_offset)));
    }
}
