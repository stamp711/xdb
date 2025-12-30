#pragma once

#include <libxdb/elf.hpp>
#include <libxdb/process.hpp>
#include <libxdb/stack.hpp>

namespace xdb {

/// Owns both process and elf and coordinates between runtime state and static binary info.
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

    void notify_stop(const xdb::stop_reason& reason);

    /// Convert current pc to file address using our managed elf object.
    ///
    /// @return The file address corresponding to the virtual address. If we can't convert the address (for example, we
    ///         can't convert addresses in dynamic libraries for now), returns an empty file_addr.
    auto get_pc_file_address() const -> file_addr;

   private:
    target(std::unique_ptr<process> proc, std::unique_ptr<elf> obj)
        : process_(std::move(proc)), elf_(std::move(obj)), stack_(*this) {}

    std::unique_ptr<process> process_;
    std::unique_ptr<elf> elf_;
    stack stack_;
};

}  // namespace xdb
