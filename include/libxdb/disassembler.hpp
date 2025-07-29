#pragma once

#include <libxdb/process.hpp>
#include <libxdb/types.hpp>
#include <optional>
#include <string>

namespace xdb {

class disassembler {
    struct instruction {
        virt_addr address;
        std::string text;
    };

   public:
    disassembler(process& process) : process_(&process) {}

    std::vector<instruction> disassemble(std::size_t n_instructions, std::optional<virt_addr> address = std::nullopt);

   private:
    process* process_;
};

}  // namespace xdb
