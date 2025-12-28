#pragma once

#include <libxdb/elf.hpp>
#include <libxdb/process.hpp>

namespace xdb {

class target {
   public:
    target() = delete;
    target(const target&) = delete;
    target(target&&) = delete;
    auto operator=(const target&) -> target& = delete;
    auto operator=(target&&) -> target& = delete;
    ~target() = default;

    static auto launch(const std::filesystem::path& path, std::optional<int> stdout_replacement = std::nullopt)
        -> std::unique_ptr<target>;
    static auto attach(pid_t pid) -> std::unique_ptr<target>;

    auto get_process() -> process& { return *process_; }
    auto get_process() const -> const process& { return *process_; }
    auto get_elf() -> elf& { return *elf_; }
    auto get_elf() const -> const elf& { return *elf_; }

   private:
    target(std::unique_ptr<process> proc, std::unique_ptr<elf> obj) : process_(std::move(proc)), elf_(std::move(obj)) {}

    std::unique_ptr<process> process_;
    std::unique_ptr<elf> elf_;
};

}  // namespace xdb
