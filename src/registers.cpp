#include <cstring>
#include <libxdb/bit.hpp>
#include <libxdb/process.hpp>
#include <libxdb/registers.hpp>
#include <utility>
#include <variant>

xdb::registers::value xdb::registers::read(const register_info& info) const {
    auto user_bytes = as_bytes(data_);

    switch (info.format) {
        case register_format::uint:
            switch (info.size) {
                case 1:
                    return from_bytes<std::uint8_t>(user_bytes + info.offset);
                case 2:
                    return from_bytes<std::uint16_t>(user_bytes + info.offset);
                case 4:
                    return from_bytes<std::uint32_t>(user_bytes + info.offset);
                case 8:
                    return from_bytes<std::uint64_t>(user_bytes + info.offset);
                default:
                    error::send("Unexpected size for uint register format: " +
                                std::to_string(info.size));
            }

        case register_format::double_float:
            return from_bytes<double>(user_bytes + info.offset);

        case register_format::long_double:
            return from_bytes<long double>(user_bytes + info.offset);

        case register_format::vector:
            switch (info.size) {
                case 8:
                    return from_bytes<byte64>(user_bytes + info.offset);
                case 16:
                    return from_bytes<byte128>(user_bytes + info.offset);
                default:
                    error::send("Unexpected size for vector register format: " +
                                std::to_string(info.size));
            }

        default:
            std::unreachable();
    }
}

void xdb::registers::write(const register_info& info, value val) {
    auto user_bytes = as_bytes(data_);

    std::visit(
        [&info, &user_bytes](auto& v) {
            if (sizeof(v) == info.size) {
                auto val_bytes = as_bytes(v);
                std::memcpy(user_bytes + info.offset, val_bytes, info.size);
            } else {
                error::send(
                    "Unexpected size for value in write operation: val size " +
                    std::to_string(sizeof(v)) + " vs register size " +
                    std::to_string(info.size));
            }
        },
        val);

    proc_->write_user_area(info.offset,
                           from_bytes<std::uint64_t>(user_bytes + info.offset));
}
