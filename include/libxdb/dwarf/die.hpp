#pragma once

#include <libxdb/dwarf/line_table.hpp>
#include <libxdb/dwarf/range_list.hpp>
#include <libxdb/dwarf/types.hpp>
#include <libxdb/types.hpp>
#include <span>

namespace xdb {
class compile_unit;

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
    auto offset_in_debug_info() const -> std::size_t;

    auto cu() const -> const compile_unit& { return *cu_; }

    auto contains(uint64_t attr) const -> bool;  // TODO: rename to contains_attr
    auto operator[](uint64_t attr) const -> class attr;
    auto abbreviation() const -> const abbrev& { return *abbrev_; }

    auto low_pc() const -> file_addr;
    auto high_pc() const -> file_addr;
    auto contains_address(file_addr address) const -> bool;

    class children_range;
    auto children() const -> children_range;

    auto name() const -> std::optional<std::string_view>;

    auto location() const -> source_location;
    auto file() const -> const line_table::file&;
    auto line() const -> uint64_t;

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

class attr {
   public:
    attr() = delete;
    attr(uint64_t type, uint64_t form, const std::byte* location, const compile_unit& cu)
        : type_(type), form_(form), location_(location), cu_(&cu) {}

    auto type() const -> uint64_t { return type_; }
    auto form() const -> uint64_t { return form_; }

    auto as_address() const -> file_addr;
    auto as_section_offset() const -> std::uint32_t;
    auto as_block() const -> std::span<const std::byte>;
    auto as_int() const -> std::uint64_t;
    auto as_string() const -> std::string_view;
    auto as_reference() const -> die;
    auto as_range_list() const -> range_list;

   private:
    uint64_t type_;
    uint64_t form_;
    const std::byte* location_;
    const compile_unit* cu_;
    // const die* die_;  // We don't store die_ because there's no storage for them in dwarf, easy to use-after-free
};

}  // namespace xdb
