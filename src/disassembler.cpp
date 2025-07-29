#include <Zycore/Status.h>
#include <Zydis/Disassembler.h>
#include <Zydis/Zydis.h>

#include <cstddef>
#include <libxdb/disassembler.hpp>

namespace xdb {

std::vector<disassembler::instruction> disassembler::disassemble(
    std::size_t n_instructions, std::optional<virt_addr> address) {
    std::vector<instruction> res;
    res.reserve(n_instructions);

    // Default address is the current program counter
    if (!address) {
        address = process_->get_pc();
    }

    const std::size_t MAX_LENGTH_OF_X86_64_INSTRUCTION = 15;
    auto code = process_->read_memory_without_traps(
        address.value(), n_instructions * MAX_LENGTH_OF_X86_64_INSTRUCTION);
    std::span<const std::byte> code_span(code.data(), code.size());

    ZydisDisassembledInstruction instr;
    while (n_instructions > 0 && !code_span.empty() &&
           ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64,
                                              address->addr(), code_span.data(),
                                              code_span.size(), &instr))) {
        res.emplace_back(*address, instr.text);
        --n_instructions;
        *address += instr.info.length;
        code_span = code_span.subspan(instr.info.length);
    }

    return res;
}

}  // namespace xdb
