#pragma once

#include <libxdb/elf.hpp>
#include <libxdb/process.hpp>

namespace xdb {

class target {
   public:
    target() = delete;
    target(const target&) = delete;
    target(target&&) = delete;
    target& operator=(const target&) = delete;
    target& operator=(target&&) = delete;
    ~target() = default;

    static std::unique_ptr<target> launch(const std::filesystem::path& path,
                                          std::optional<int> stdout_replacement = std::nullopt);
    static std::unique_ptr<target> attach(pid_t pid);

    process& get_process() { return *process_; }
    [[nodiscard]] const process& get_process() const { return *process_; }
    elf& get_elf() { return *elf_; }
    [[nodiscard]] const elf& get_elf() const { return *elf_; }

   private:
    target(std::unique_ptr<process> proc, std::unique_ptr<elf> obj) : process_(std::move(proc)), elf_(std::move(obj)) {}

    std::unique_ptr<process> process_;
    std::unique_ptr<elf> elf_;
};

}  // namespace xdb
