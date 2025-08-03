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

std::byte replace_byte_in_process(xdb::process& proc, xdb::virt_addr address, std::byte new_byte) {
    // return original_byte;
    auto original_byte = proc.read_memory_as<std::byte>(address);
    proc.write_memory(address, std::span(&new_byte, 1));
    return original_byte;
}

}  // namespace

xdb::breakpoint_site::breakpoint_site(process& proc, virt_addr address, bool is_hardware, bool is_internal)
    : process_(&proc),
      address_(address),
      is_enabled_(false),
      original_byte_{},
      is_hardware_(is_hardware),
      is_internal_(is_internal) {
    id_ = is_internal_ ? -1 : get_next_id();
}

void xdb::breakpoint_site::enable() {
    if (is_enabled_) return;

    if (is_hardware_) {
        hardware_register_index_ =
            process_->set_hardware_stoppoint_(address_, stoppoint_mode::execute, 1 /* must be 1 for execute */);
    } else /* Software breakpoint */ {
        const std::byte INT3{0xCC};
        original_byte_ = replace_byte_in_process(*process_, address_, INT3);
    }

    is_enabled_ = true;
}

void xdb::breakpoint_site::disable() {
    if (!is_enabled_) return;

    if (is_hardware_) {
        process_->clear_hardware_stoppoint_(hardware_register_index_);
    } else /* Software breakpoint */ {
        replace_byte_in_process(*process_, address_, original_byte_);
    }

    is_enabled_ = false;
}
