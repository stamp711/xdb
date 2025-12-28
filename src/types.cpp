#include <libxdb/elf.hpp>
#include <libxdb/types.hpp>
#include <optional>

namespace xdb {

auto file_addr::to_virt_addr() const -> std::optional<virt_addr> {
    const auto* shdr = elf_->get_section_header_containing_file_addr(*this);
    if (shdr == nullptr) return std::nullopt;
    return virt_addr(elf_->load_bias().addr() + addr_);
}

auto virt_addr::to_file_addr(const elf& obj) const -> std::optional<file_addr> {
    const auto* shdr = obj.get_section_header_containing_virt_addr(*this);
    if (shdr == nullptr) return std::nullopt;
    return file_addr(obj, addr_ - obj.load_bias().addr());
}

}  // namespace xdb
