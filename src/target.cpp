#include <libxdb/target.hpp>
#include <libxdb/types.hpp>
#include <memory>

namespace {

std::unique_ptr<xdb::elf> create_loaded_elf(const xdb::process& process, const std::filesystem::path& path) {
    auto auxv = process.get_auxv();
    auto elf = std::make_unique<xdb::elf>(path);
    auto load_bias = auxv[AT_ENTRY] - elf->header().e_entry;
    elf->notify_load_bias(xdb::virt_addr(load_bias));
    return elf;
}

}  // namespace

namespace xdb {

std::unique_ptr<target> target::launch(const std::filesystem::path& path, std::optional<int> stdout_replacement) {
    auto process = process::launch(path, true, stdout_replacement);
    auto elf = create_loaded_elf(*process, path);
    return std::unique_ptr<target>(new target(std::move(process), std::move(elf)));
}

std::unique_ptr<target> target::attach(pid_t pid) {
    auto process = process::attach(pid);
    auto elf_path = std::filesystem::path("/proc") / std::to_string(pid) / "exe";
    auto elf = create_loaded_elf(*process, elf_path);
    return std::unique_ptr<target>(new target(std::move(process), std::move(elf)));
}

}  // namespace xdb
