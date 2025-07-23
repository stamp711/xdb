#include <sys/ptrace.h>

#include <libxdb/breakpoint_site.hpp>
#include <libxdb/error.hpp>
#include <libxdb/process.hpp>
#include <libxdb/types.hpp>

namespace {

auto get_next_id() {
    static std::int32_t current_id = 0;
    return ++current_id;
}

std::byte replace_byte_in_process(xdb::process& proc, xdb::virt_addr address,
                                  std::byte new_byte) {
    // Align address to word size
    std::uint64_t aligned_address =
        address.addr() & ~0x7ull;  // Align to word size (8 bytes)
    const size_t byte_shift = address.addr() & 0x7;
    const size_t bit_shift = byte_shift * 8;

    errno = 0;
    auto original_word = static_cast<std::uint64_t>(
        ::ptrace(PTRACE_PEEKDATA, proc.pid(), aligned_address, nullptr));
    if (errno != 0) {
        xdb::error::send_errno("Failed to read data at address");
    }

    auto original_byte =
        static_cast<std::byte>((original_word >> bit_shift) & 0xFFull);

    const std::uint64_t modified_word =
        (original_word & ~(0xFFull << bit_shift)) |
        (static_cast<std::uint64_t>(new_byte) << bit_shift);

    if (::ptrace(PTRACE_POKEDATA, proc.pid(), aligned_address, modified_word) ==
        -1) {
        xdb::error::send_errno("Failed to write to address");
    }

    return original_byte;
}

}  // namespace

xdb::breakpoint_site::breakpoint_site(process& proc, virt_addr address)
    : id_(get_next_id()),
      process_(&proc),
      address_(address),
      is_enabled_(false),
      original_byte_{} {}

void xdb::breakpoint_site::enable() {
    const std::byte INT3{0xCC};
    if (!is_enabled_) {
        original_byte_ = replace_byte_in_process(*process_, address_, INT3);
        is_enabled_ = true;
    }
}

void xdb::breakpoint_site::disable() {
    if (is_enabled_) {
        replace_byte_in_process(*process_, address_, original_byte_);
        is_enabled_ = false;
    }
}
