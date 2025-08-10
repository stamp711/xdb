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

    [[nodiscard]] const std::byte* data() const noexcept { return span_.data(); }

    cursor& operator++() { return span_ = span_.subspan(1), *this; }
    cursor& operator+=(std::size_t offset) { return span_ = span_.subspan(offset), *this; }

    [[nodiscard]] bool finished() const noexcept { return span_.empty(); }

    template <class T>
    T get_fixed_int() {
        auto t = xdb::from_bytes<T>(span_.data());
        *this += sizeof(T);
        return t;
    }

    std::uint8_t get_u8() { return get_fixed_int<std::uint8_t>(); }
    std::uint16_t get_u16() { return get_fixed_int<std::uint16_t>(); }
    std::uint32_t get_u32() { return get_fixed_int<std::uint32_t>(); }
    std::uint64_t get_u64() { return get_fixed_int<std::uint64_t>(); }
    std::int8_t get_i8() { return get_fixed_int<std::int8_t>(); }
    std::int16_t get_i16() { return get_fixed_int<std::int16_t>(); }
    std::int32_t get_i32() { return get_fixed_int<std::int32_t>(); }
    std::int64_t get_i64() { return get_fixed_int<std::int64_t>(); }

    std::string_view get_string() {
        auto null_terminator = std::ranges::find(span_, std::byte{0});
        auto strlen = static_cast<std::size_t>(null_terminator - span_.begin());
        std::string_view ret(reinterpret_cast<const char*>(span_.data()), strlen);
        *this += (strlen + 1);
        return ret;
    }

    std::uint64_t get_uleb128() {
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

    std::int64_t get_sleb128() {
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
    dwarf& operator=(const dwarf&) = delete;
    dwarf& operator=(dwarf&&) = delete;

    [[nodiscard]] const elf& elf_file() const { return *elf_; }
    [[nodiscard]] std::span<const std::byte> debug_info() const { return debug_info_span_; }
    [[nodiscard]] const std::unordered_map<std::uint64_t, abbrev>& get_abbrev_table(std::size_t byte_offset);
    [[nodiscard]] const std::vector<std::unique_ptr<compile_unit>>& compile_units() const { return compile_units_; }

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

    [[nodiscard]] const dwarf& dwarf_info() const { return *parent; }
    [[nodiscard]] std::span<const std::byte> span() const { return span_; }
    [[nodiscard]] const std::unordered_map<std::uint64_t, abbrev>& abbrev_table() const {
        return parent->get_abbrev_table(abbrev_offset_);
    }

    [[nodiscard]] die root() const;

   private:
    dwarf* parent;
    std::span<const std::byte> span_;
    std::size_t abbrev_offset_;
};

class die {
   public:
    die() = delete;

    // Constructor for null (terminator) DIEs, only cu_ and next_ is valid
    static die null(const compile_unit& cu, const std::byte* next) { return die(&cu, next, {}, nullptr, {}); }

    // Constructor for non-null DIEs
    static die non_null(const compile_unit& cu, const std::byte* next, std::span<const std::byte> span,
                        const abbrev& abbrev, std::vector<const std::byte*> attr_locs) {
        return die(&cu, next, span, &abbrev, std::move(attr_locs));
    }

    [[nodiscard]] bool is_null() const { return abbrev_ == nullptr; }
    [[nodiscard]] std::span<const std::byte> next_die_parse_span() const;

    // calling any public method below for null DIE is UB.

    [[nodiscard]] std::span<const std::byte> span() const { return span_; }
    [[nodiscard]] std::size_t offset_in_debug_info() const {
        return static_cast<std::size_t>(span_.data() - cu_->dwarf_info().debug_info().data());
    }

    class children_range;
    [[nodiscard]] children_range children() const;

    [[nodiscard]] bool contains(dw_attr_type_t attr) const;
    [[nodiscard]] attr operator[](dw_attr_type_t attr) const;
    [[nodiscard]] const abbrev& abbreviation() const { return *abbrev_; }

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

        const die& operator*() const { return die_.value(); }
        const die* operator->() const { return &die_.value(); }

        iterator& operator++();
        iterator operator++(int) {
            iterator tmp = *this;
            ++(*this);
            return tmp;
        }

        bool operator==(const iterator& other) const;
        bool operator!=(const iterator& other) const { return !(*this == other); }

       private:
        std::optional<die> die_;
    };

    [[nodiscard]] iterator begin() const {
        if (die_.abbrev_->has_children) {
            return iterator{die_};
        }
        return end();
    }
    [[nodiscard]] static iterator end() { return iterator{}; }

   private:
    die die_;
};

template <dw_form_t Form>
struct form_type;

template <>
struct form_type<dw_form_t::DW_FORM_addr> {
    using type = file_addr;
};

template <>
struct form_type<dw_form_t::DW_FORM_sec_offset> {
    using type = std::uint32_t;
};

class attr {
   public:
    attr() = delete;
    attr(dw_attr_type_t type, dw_form_t form, const std::byte* location, const compile_unit& cu, const die& die)
        : type_(type), form_(form), location_(location), cu_(&cu), die_(&die) {}

    [[nodiscard]] dw_attr_type_t type() const { return type_; }
    [[nodiscard]] dw_form_t form() const { return form_; }

    template <dw_form_t Form>
    [[nodiscard]] typename form_type<Form>::type get() const;

   private:
    dw_attr_type_t type_;
    dw_form_t form_;
    const std::byte* location_;
    const compile_unit* cu_;
    const die* die_;
};

}  // namespace xdb
