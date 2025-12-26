#pragma once

#include <libxdb/detail/dwarf.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <libxdb/bit.hpp>
#include <libxdb/error.hpp>
#include <libxdb/types.hpp>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace xdb {

class elf;
class die;
class compile_unit;
class attr;
class range_list;

struct attr_spec {
    dw_attr_type_t type;
    dw_form_t form;
    std::int64_t implicit_const_value;  // For DW_FORM_implicit_const
};

struct abbrev {
    std::uint64_t code;
    dw_tag_t tag;
    bool has_children;
    std::vector<attr_spec> attrs;
};

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

    void skip_form(dw_form_t form);

   private:
    std::span<const std::byte> span_;
};

class dwarf {
   public:
    dwarf(const elf& parent_elf);

    ~dwarf() = default;
    dwarf(const dwarf&) = delete;
    dwarf(dwarf&&) = delete;

    auto operator=(const dwarf&) -> dwarf& = delete;
    auto operator=(dwarf&&) -> dwarf& = delete;

    auto elf_file() const -> const elf& { return *elf_; }
    auto debug_info() const -> std::span<const std::byte> { return debug_info_span_; }
    auto get_abbrev_table(std::size_t byte_offset) -> const std::unordered_map<std::uint64_t, abbrev>&;
    auto compile_units() const -> const std::vector<std::unique_ptr<compile_unit>>& { return compile_units_; }

   private:
    const elf* elf_;
    std::span<const std::byte> debug_info_span_;
    std::unordered_map<std::size_t, std::unique_ptr<const std::unordered_map<std::uint64_t, abbrev>>>
        abbrev_table_cache_;
    std::vector<std::unique_ptr<compile_unit>> compile_units_;
};

class compile_unit {
   public:
    compile_unit(dwarf& parent_dwarf, std::span<const std::byte> span, std::size_t abbrev_offset)
        : parent(&parent_dwarf), span_(span), abbrev_offset_(abbrev_offset) {}

    auto dwarf_info() const -> const dwarf& { return *parent; }
    auto span() const -> std::span<const std::byte> { return span_; }
    auto abbrev_table() const -> const std::unordered_map<std::uint64_t, abbrev>& {
        return parent->get_abbrev_table(abbrev_offset_);
    }

    auto root() const -> die;

   private:
    dwarf* parent;
    std::span<const std::byte> span_;
    std::size_t abbrev_offset_;
};

class die {
   public:
    die() = delete;

    // Constructor for null (terminator) DIEs, only cu_ and next_ is valid
    static auto null(const compile_unit& cu, const std::byte* next) -> die { return die(&cu, next, {}, nullptr, {}); }

    // Constructor for non-null DIEs
    static auto non_null(const compile_unit& cu, const std::byte* next, std::span<const std::byte> span,
                         const abbrev& abbrev, std::vector<const std::byte*> attr_locs) -> die {
        return die(&cu, next, span, &abbrev, std::move(attr_locs));
    }

    auto is_null() const -> bool { return abbrev_ == nullptr; }
    auto next_die_parse_span() const -> std::span<const std::byte>;

    // calling any public method below for null DIE is UB.

    auto span() const -> std::span<const std::byte> { return span_; }
    auto offset_in_debug_info() const -> std::size_t {
        return static_cast<std::size_t>(span_.data() - cu_->dwarf_info().debug_info().data());
    }

    auto contains(dw_attr_type_t attr) const -> bool;
    auto operator[](dw_attr_type_t attr) const -> class attr;
    auto abbreviation() const -> const abbrev& { return *abbrev_; }

    auto low_pc() const -> file_addr;
    auto high_pc() const -> file_addr;
    auto contains_address(file_addr address) const -> bool;

    class children_range;
    auto children() const -> children_range;

   private:
    explicit die(const compile_unit* cu, const std::byte* next, std::span<const std::byte> span, const abbrev* abbrev,
                 std::vector<const std::byte*> attr_locs)
        : cu_(cu), next_(next), span_(span), abbrev_(abbrev), attr_locs_(std::move(attr_locs)) {}

    const compile_unit* cu_;  // always valid
    const std::byte* next_;   // always valid
    std::span<const std::byte> span_;
    const abbrev* abbrev_;
    std::vector<const std::byte*> attr_locs_;
};

class die::children_range {
   public:
    // DIE must be non-null
    explicit children_range(die die) : die_(std::move(die)) {}

    class iterator {
       public:
        using iterator_category = std::forward_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using value_type = die;
        using pointer = const die*;
        using reference = const die&;

        explicit iterator() = default;
        explicit iterator(const die& die);

        auto operator*() const -> const die& { return die_.value(); }
        auto operator->() const -> const die* { return &die_.value(); }

        auto operator++() -> iterator&;
        auto operator++(int) -> iterator {
            iterator tmp = *this;
            ++(*this);
            return tmp;
        }

        auto operator==(const iterator& other) const -> bool;
        auto operator!=(const iterator& other) const -> bool { return !(*this == other); }

       private:
        std::optional<die> die_;
    };

    auto begin() const -> iterator {
        if (die_.abbrev_->has_children) {
            return iterator{die_};
        }
        return end();
    }
    auto end() const -> iterator { return iterator{}; }

   private:
    die die_;
};

class range_list;
class attr {
   public:
    attr() = delete;
    attr(dw_attr_type_t type, dw_form_t form, const std::byte* location, const compile_unit& cu)
        : type_(type), form_(form), location_(location), cu_(&cu) {}

    auto type() const -> dw_attr_type_t { return type_; }
    auto form() const -> dw_form_t { return form_; }

    auto as_address() const -> file_addr;
    auto as_section_offset() const -> std::uint32_t;
    auto as_block() const -> std::span<const std::byte>;
    auto as_int() const -> std::uint64_t;
    auto as_string() const -> std::string_view;
    auto as_reference() const -> die;
    auto as_range_list() const -> range_list;

   private:
    dw_attr_type_t type_;
    dw_form_t form_;
    const std::byte* location_;
    const compile_unit* cu_;
    // const die* die_;  // We don't store die_ because there's no storage for them in dwarf, easy to use-after-free
};

/* ========== range list related ========== */

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

    ~iterator() = default;

    iterator() = default;
    iterator(iterator&&) = default;
    auto operator=(iterator&&) -> iterator& = default;
    iterator(const iterator& other) = default;
    auto operator=(const iterator&) -> iterator& = default;

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
