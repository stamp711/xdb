#pragma once

#include <sys/user.h>

#include <libxdb/register_info.hpp>
#include <libxdb/types.hpp>
#include <variant>

namespace xdb {

class process;

class registers {
   public:
    registers() = delete;
    registers(const registers&) = delete;
    registers(registers&&) = delete;
    registers& operator=(const registers&) = delete;
    registers& operator=(registers&&) = delete;
    ~registers() = default;

    using value =
        std::variant<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t,
                     std::int8_t, std::int16_t, std::int32_t, std::int64_t,
                     float, double, long double, byte64, byte128>;

    [[nodiscard]] value read(const register_info& info) const;
    void write(const register_info& info, value val);

    template <class T>
    [[nodiscard]] T read_by_id_as(register_id register_identifier) const {
        return std::get<T>(read(register_info_by_id(register_identifier)));
    }
    void write_by_id(register_id id, value val) {
        write(register_info_by_id(id), val);
    }

   private:
    friend process;
    registers(process* proc) : data_{}, proc_(proc) {}

    user data_;
    process* proc_;
};

}  // namespace xdb
