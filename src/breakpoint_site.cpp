#include <sys/ptrace.h>

#include <cstddef>
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
    // return original_byte;
    auto original_byte = proc.read_memory_as<std::byte>(address);
    proc.write_memory(address, std::span(&new_byte, 1));
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
