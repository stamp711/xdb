#pragma once

#include <elf.h>

#include <cstddef>
#include <deque>
#include <filesystem>
#include <libxdb/dwarf.hpp>
#include <libxdb/types.hpp>
#include <map>
#include <span>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace xdb {

class elf {
   public:
    elf(std::filesystem::path path);
    ~elf();

    elf(const elf&) = delete;
    elf(elf&&) = delete;
    auto operator=(const elf&) -> elf& = delete;
    auto operator=(elf&&) -> elf& = delete;

    auto operator==(const elf& other) const noexcept -> bool { return path_ == other.path_ && data_ == other.data_; }

    auto path() const noexcept -> std::filesystem::path { return path_; }
    auto header() const noexcept -> const Elf64_Ehdr& { return header_; }

    void notify_load_bias(virt_addr bias) noexcept { load_bias_ = bias; }
    auto load_bias() const -> virt_addr {
        assert_load_bias_set_();
        return load_bias_;
    }

    // Section related
    auto get_section_header(std::string_view name) const -> const Elf64_Shdr*;
    auto get_section_contents(std::string_view name) const -> std::span<const std::byte>;
    auto get_section_start_file_addr(std::string_view name) const -> std::optional<file_addr>;
    auto get_section_start_virt_addr(std::string_view name) const -> std::optional<virt_addr>;
    auto get_section_header_containing_file_addr(file_addr file_addr) const -> const Elf64_Shdr*;
    auto get_section_header_containing_virt_addr(virt_addr virt_addr) const -> const Elf64_Shdr*;

    auto get_string(std::size_t index) const -> std::string_view;

    // Symbols related
    auto get_symbols_by_name(std::string_view name) const -> std::vector<const Elf64_Sym*>;
    auto get_symbol_at_file_addr(file_addr file_addr) const -> const Elf64_Sym*;
    auto get_symbol_at_virt_addr(virt_addr virt_addr) const -> const Elf64_Sym*;
    auto get_symbol_containing_file_addr(file_addr file_addr) const -> const Elf64_Sym*;
    auto get_symbol_containing_virt_addr(virt_addr virt_addr) const -> const Elf64_Sym*;

    auto get_dwarf() -> dwarf& { return *dwarf_; }
    auto get_dwarf() const -> const dwarf& { return *dwarf_; }

   private:
    void assert_load_bias_set_() const;
    void parse_section_headers_();
    void build_section_map_();
    void parse_symbol_table_();
    void build_symbol_maps_();

    auto get_section_name_(std::size_t index) const -> std::string_view;

    std::filesystem::path path_;
    int fd_ = -1;  // fd for opened ELF file
    std::size_t file_size_;
    std::byte* data_ = nullptr;  // mmaped pointer to ELF file contents

    Elf64_Ehdr header_{};

    // Section headers and name->section header map
    std::span<const Elf64_Shdr> section_headers_;
    std::unordered_map<std::string_view, const Elf64_Shdr*> section_header_map_;  // name -> section header

    // Symbol table
    std::span<const Elf64_Sym> symbol_table_;
    std::deque<std::string> demangled_symbol_names_;  // deque prevents iterator invalidation on growth
    std::unordered_multimap<std::string_view, const Elf64_Sym*> symbol_name_map_;  // name (raw,demangled) -> symbol
    struct addr_range_cmp {
        using is_transparent = std::true_type;
        // Look up by range - only compare starting address
        auto operator()(const std::pair<file_addr, file_addr>& lhs, const std::pair<file_addr, file_addr>& rhs) const
            -> bool {
            return lhs.first < rhs.first;
        }
        // range < file_addr
        auto operator()(const std::pair<file_addr, file_addr>& lhs, const file_addr& addr) const -> bool {
            return lhs.second <= addr;
        }
        // file_addr < range
        auto operator()(const file_addr& addr, const std::pair<file_addr, file_addr>& rhs) const -> bool {
            return addr < rhs.first;
        }
    };
    std::map<std::pair<file_addr, file_addr>, const Elf64_Sym*, addr_range_cmp>
        symbol_addr_map_;  // addr range -> symbol

    virt_addr load_bias_{0};

    std::unique_ptr<dwarf> dwarf_;
};

}  // namespace xdb
