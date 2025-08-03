#include <cxxabi.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstddef>
#include <cstring>
#include <functional>
#include <libxdb/bit.hpp>
#include <libxdb/elf.hpp>
#include <libxdb/error.hpp>
#include <optional>

namespace {
class scope_guard {
    std::function<void()> fn_;
    bool active_ = true;

   public:
    explicit scope_guard(std::function<void()> fn) : fn_(std::move(fn)) {}
    ~scope_guard() {
        if (active_) fn_();
    }
    scope_guard(const scope_guard&) = delete;
    scope_guard(scope_guard&&) = delete;
    scope_guard& operator=(const scope_guard&) = delete;
    scope_guard& operator=(scope_guard&&) = delete;

    void dismiss() { active_ = false; }
};
}  // namespace

namespace xdb {

elf::elf(std::filesystem::path path) : path_(std::move(path)) {
    auto fd = open(path_.string().c_str(), O_RDONLY);
    if (fd < 0) {
        error::send_errno("Could not open ELF file");
    }
    fd_ = fd;
    scope_guard guard_fd([this]() {
        if (fd_ >= 0) {
            close(fd_);
        }
    });

    struct stat st{};
    if (fstat(fd_, &st) < 0) {
        error::send_errno("Could not stat ELF file");
    }
    file_size_ = static_cast<std::size_t>(st.st_size);

    auto* addr = static_cast<std::byte*>(mmap(nullptr, file_size_, PROT_READ, MAP_PRIVATE, fd_, 0));
    if (addr == MAP_FAILED) {
        error::send_errno("Could not mmap ELF file");
    }
    data_ = addr;
    scope_guard guard_mmap([this]() {
        if (data_) {
            munmap(data_, file_size_);
        }
    });

    std::memcpy(&header_, data_, sizeof(Elf64_Ehdr));

    parse_section_headers_();
    build_section_map_();
    parse_symbol_table_();
    build_symbol_maps_();

    // Dismiss the scope guards, the destructor will handle them
    guard_fd.dismiss();
    guard_mmap.dismiss();
}

elf::~elf() {
    if (data_ != nullptr) {
        munmap(data_, file_size_);
    }
    if (fd_ >= 0) {
        close(fd_);
    }
}

const Elf64_Shdr* elf::get_section_header(std::string_view name) const {
    auto it = section_header_map_.find(name);
    if (it == section_header_map_.end()) {
        return nullptr;
    }
    return it->second;
}

std::span<const std::byte> elf::get_section_contents(std::string_view name) const {
    const auto* shdr = get_section_header(name);
    if (shdr == nullptr) {
        return {};
    }
    auto offset = shdr->sh_offset;
    auto size = shdr->sh_size;
    return {data_ + offset, size};
}

std::optional<file_addr> elf::get_section_start_file_addr(std::string_view name) const {
    const auto* shdr = get_section_header(name);
    if (shdr == nullptr) {
        return std::nullopt;
    }
    return file_addr(*this, shdr->sh_offset);
}

std::optional<virt_addr> elf::get_section_start_virt_addr(std::string_view name) const {
    const auto* shdr = get_section_header(name);
    if (shdr == nullptr) {
        return std::nullopt;
    }
    assert_load_bias_set_();
    return virt_addr(load_bias_ + shdr->sh_addr);
}

const Elf64_Shdr* elf::get_section_header_containing_file_addr(file_addr file_addr) const {
    if (file_addr.elf_file() != this) return nullptr;
    for (const auto& shdr : section_headers_) {
        if (shdr.sh_addr <= file_addr.addr() && file_addr.addr() < shdr.sh_addr + shdr.sh_size) {
            return &shdr;
        }
    }
    return nullptr;
}

const Elf64_Shdr* elf::get_section_header_containing_virt_addr(virt_addr virt_addr) const {
    assert_load_bias_set_();
    for (const auto& shdr : section_headers_) {
        if (load_bias_ + shdr.sh_addr <= virt_addr && virt_addr < load_bias_ + shdr.sh_addr + shdr.sh_size) {
            return &shdr;
        }
    }
    return nullptr;
}

std::string_view elf::get_string(std::size_t index) const {
    // NOTE: Although most ELF files have a general string table, in some cases they may allocate different string
    // tables to different sections.
    //
    // The more robust way to handle string tables is to read the sh_link field of the section header to which the
    // string table index belongs, which provides the section index of the string table for that section.
    //
    // We've opted to assume there’s a general string table for simplicity.
    auto strs = get_section_contents(".strtab");
    if (strs.empty()) strs = get_section_contents(".dynstr");
    if (strs.empty()) return {};
    return {reinterpret_cast<const char*>(&strs[index])};
}

std::vector<const Elf64_Sym*> elf::get_symbols_by_name(std::string_view name) const {
    const auto [begin, end] = symbol_name_map_.equal_range(name);
    std::vector<const Elf64_Sym*> res;
    std::transform(begin, end, std::back_inserter(res), [](const auto& it) { return it.second; });
    return res;
}

const Elf64_Sym* elf::get_symbol_at_file_addr(file_addr file_addr) const {
    if (file_addr.elf_file() != this) return nullptr;
    auto it = symbol_addr_map_.find({file_addr, file_addr});
    if (it != symbol_addr_map_.end()) {
        return it->second;
    }
    return nullptr;
}

const Elf64_Sym* elf::get_symbol_at_virt_addr(virt_addr virt_addr) const {
    auto file_addr = virt_addr.to_file_addr(*this);
    if (file_addr == std::nullopt) return nullptr;
    return get_symbol_containing_file_addr(*file_addr);
}

const Elf64_Sym* elf::get_symbol_containing_file_addr(file_addr file_addr) const {
    if (file_addr.elf_file() != this) return nullptr;

    // Use equal_range to find all ranges that could contain this address
    auto [begin_it, end_it] = symbol_addr_map_.equal_range(file_addr);

    // Check if equal_range returned empty
    if (begin_it == end_it) {
        return nullptr;
    }

    // Return the last entry in the range (largest start address = most specific)
    --end_it;
    return end_it->second;
}

const Elf64_Sym* elf::get_symbol_containing_virt_addr(virt_addr virt_addr) const {
    auto file_addr = virt_addr.to_file_addr(*this);
    if (file_addr == std::nullopt) return nullptr;
    return get_symbol_containing_file_addr(*file_addr);
}

void elf::assert_load_bias_set_() const { assert(load_bias_.addr() != 0); }

void elf::parse_section_headers_() {
    if (header_.e_shoff == 0 || header_.e_shentsize == 0) {
        return;  // No section headers to parse
    }

    // Verify section header size
    auto sh_entsize = header_.e_shentsize;
    if (sh_entsize != sizeof(Elf64_Shdr)) {
        error::send("Unexpected section header size");
    }

    const auto* sh_start = reinterpret_cast<const Elf64_Shdr*>(data_ + header_.e_shoff);
    std::uint64_t n_headers = header_.e_shnum;

    // Ref: https://refspecs.linuxbase.org/elf/gabi4+/ch4.sheader.html
    //
    // If the number of sections is greater than or equal to SHN_LORESERVE (0xff00), e_shnum has the value SHN_UNDEF (0)
    // and the actual number of section header table entries is contained in the sh_size field of the section header at
    // index 0 (otherwise, the sh_size member of the initial entry contains 0).
    if (n_headers == 0) {
        n_headers = sh_start->sh_size;
    }

    section_headers_ = {sh_start, n_headers};
}

void elf::build_section_map_() {
    section_header_map_.clear();
    for (const auto& section_header : section_headers_) {
        section_header_map_[get_strtab_string_(section_header.sh_name)] = &section_header;
    }
}

void elf::parse_symbol_table_() {
    const auto* syms_shdr = get_section_header(".symtab");
    if (syms_shdr == nullptr) syms_shdr = get_section_header(".dynsym");
    if (syms_shdr == nullptr) return;

    // Verify section entry size
    if (syms_shdr->sh_entsize != sizeof(Elf64_Sym)) {
        error::send("Unexpected symbol table entry size");
    }

    const auto* syms_start = reinterpret_cast<const Elf64_Sym*>(data_ + syms_shdr->sh_offset);
    auto n_symbols = syms_shdr->sh_size / syms_shdr->sh_entsize;

    symbol_table_ = {syms_start, n_symbols};
}

void elf::build_symbol_maps_() {
    for (const auto& symbol : symbol_table_) {
        // TODO: what if st_name or st_value is 0?

        // Insert raw name -> symbol map
        auto raw_name = get_string(symbol.st_name);
        symbol_name_map_.emplace(raw_name, &symbol);

        // Insert demangled name -> symbol map
        int status = 0;
        std::unique_ptr<char, decltype(&std::free)> demangled_name_ptr(nullptr, &std::free);
        demangled_name_ptr.reset(abi::__cxa_demangle(std::string(raw_name).c_str(), nullptr, nullptr, &status));
        if (status == 0 && demangled_name_ptr) {
            demangled_symbol_names_.emplace_back(demangled_name_ptr.get());
            symbol_name_map_.emplace(demangled_symbol_names_.back(), &symbol);
        }

        // Insert addr range -> symbol map
        if (symbol.st_value != 0 && symbol.st_name != 0 && ELF64_ST_TYPE(symbol.st_info) != STT_TLS) {
            auto start = file_addr(*this, symbol.st_value);
            auto end = file_addr(*this, symbol.st_value + symbol.st_size);
            auto addr_range = std::pair(start, end);
            symbol_addr_map_.emplace(addr_range, &symbol);
        }
    }
}

std::string_view elf::get_strtab_string_(std::size_t index) const {
    const auto* strtab = &section_headers_[header_.e_shstrndx];
    return {reinterpret_cast<const char*>(strtab) + index};
}

}  // namespace xdb
