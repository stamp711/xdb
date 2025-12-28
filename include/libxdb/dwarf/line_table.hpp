#pragma once

#include <fmt/ostream.h>

#include <cstdint>
#include <filesystem>
#include <libxdb/types.hpp>
#include <vector>

namespace xdb {

class compile_unit;

class line_table {
   public:
    // represent file entries
    struct file {
        std::filesystem::path path;
        uint64_t directory_index;
        std::uint64_t timestamp;
        std::uint64_t size;
        // TODO: MD5?
    };

    struct entry;

    ~line_table() = default;

    line_table(const line_table&) = delete;
    auto operator=(const line_table&) -> line_table& = delete;

    line_table(line_table&&) = delete;
    auto operator=(line_table&&) -> line_table& = delete;

    line_table(std::span<const std::byte> data, const compile_unit& cu, bool default_is_stmt, int8_t line_base,
               uint8_t line_range, uint8_t opcode_base, std::vector<std::filesystem::path> directories,
               std::vector<file> file_names)
        : data_(data),
          cu_(&cu),
          default_is_stmt_(default_is_stmt),
          line_base_(line_base),
          line_range_(line_range),
          opcode_base_(opcode_base),
          directories_(std::move(directories)),
          file_names_(std::move(file_names)) {}

    auto initial_state() const -> entry;

    auto cu() const -> const compile_unit& { return *cu_; }
    auto file_names() const -> const std::vector<file>& { return file_names_; }

    class iterator;
    auto begin() const -> iterator;
    auto end() const -> iterator;

    auto get_entry_by_address(file_addr address) const -> iterator;
    auto get_entries_by_line(const std::filesystem::path& path, uint64_t line) const -> std::vector<iterator>;

   private:
    std::span<const std::byte> data_;
    const compile_unit* cu_;

    // Necessary infos from the header. See P.153: Line Number Program Header
    bool default_is_stmt_;  // The initial value of the is_stmt register.
    int8_t line_base_;
    uint8_t line_range_;
    uint8_t opcode_base_;

    std::vector<std::filesystem::path> directories_;
    std::vector<file> file_names_;
};

struct source_location {
    const line_table::file* file;
    uint64_t line;
};

// P.153: Line number program initial state
struct line_table::entry {
    file_addr address;
    // uint64_t op_index = 0;
    uint64_t file = 1;
    uint64_t line = 1;
    uint64_t column = 0;
    bool is_stmt = false;  // should init to default_is_stmt in line table header
    bool basic_block = false;
    bool end_sequence = false;
    bool prologue_end = false;
    bool epilogue_begin = false;
    // uint64_t isa = 0;
    uint64_t discriminator = 0;

    entry(bool is_stmt_v) : is_stmt(is_stmt_v) {}

    const struct file* file_entry = nullptr;

    auto operator==(const entry& other) const -> bool {
        // file + line + column + discriminator
        return address == other.address && file == other.file && line == other.line && column == other.column &&
               discriminator == other.discriminator;
    }

    friend auto operator<<(std::ostream& os, const entry& p) -> std::ostream& {
        return os << "entry { address: " << p.address << ", file: " << p.file << ", line: " << p.line
                  << ", column: " << p.column << ", is_stmt: " << p.is_stmt << ", basic_block: " << p.basic_block
                  << ", end_sequence: " << p.end_sequence << ", prologue_end: " << p.prologue_end
                  << ", epilogue_begin: " << p.epilogue_begin << ", discriminator: " << p.discriminator << " }";
    }
};

class line_table::iterator {
   public:
    using iterator_category = std::forward_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using value_type = entry;
    using reference = const entry&;
    using pointer = const entry*;

    explicit iterator(const line_table& table)
        : table_(&table),
          current_(table.default_is_stmt_),
          registers_(table.default_is_stmt_),
          pos_(table.data_.data()) {
        ++(*this);
    }
    iterator() : table_(nullptr), current_(false), registers_(false), pos_(nullptr) {}

    auto operator*() const -> reference { return current_; }
    auto operator->() const -> pointer { return &current_; }

    auto operator==(const iterator& other) const -> bool { return pos_ == other.pos_; }
    auto operator!=(const iterator& other) const -> bool { return pos_ != other.pos_; }

    auto operator++() -> iterator&;
    auto operator++(int) -> iterator {
        iterator tmp = *this;
        ++(*this);
        return tmp;
    }

   private:
    auto execute_instruction_() -> bool;

    const line_table* table_;
    line_table::entry current_;
    line_table::entry registers_;
    const std::byte* pos_;
};

}  // namespace xdb
