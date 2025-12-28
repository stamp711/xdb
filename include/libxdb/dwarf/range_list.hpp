#pragma once

#include <libxdb/types.hpp>
#include <span>

namespace xdb {

class compile_unit;

class range_list {
   public:
    range_list(const compile_unit& cu, std::span<const std::byte> data, file_addr base_address)
        : cu_(&cu), data_(data), base_address_(base_address) {}

    struct entry {
        file_addr low;
        file_addr high;
        auto contains(file_addr addr) const -> bool { return low <= addr && addr < high; }
    };

    class iterator;
    auto begin() const -> iterator;
    auto end() const -> iterator;

    auto contains(file_addr addr) const -> bool;

   private:
    const compile_unit* cu_;  // always valid
    std::span<const std::byte> data_;
    file_addr base_address_;
};

class range_list::iterator {
   public:
    using value_type = entry;
    using difference_type = std::ptrdiff_t;
    using pointer = const entry*;
    using reference = const entry&;
    using iterator_category = std::forward_iterator_tag;

    iterator(const compile_unit& cu, std::span<const std::byte> data, file_addr base_address);
    iterator() = default;

    auto operator*() const -> reference { return current_; }
    auto operator->() const -> pointer { return &current_; }

    auto operator==(const iterator& other) const -> bool { return pos_ == other.pos_; }
    auto operator!=(const iterator& other) const -> bool { return pos_ != other.pos_; }

    auto operator++() -> iterator&;
    auto operator++(int) -> iterator {
        auto tmp = *this;
        ++(*this);
        return tmp;
    }

   private:
    const compile_unit* cu_ = nullptr;
    std::span<const std::byte> data_;
    file_addr base_address_;
    const std::byte* pos_ = nullptr;
    entry current_;
};
}  // namespace xdb
