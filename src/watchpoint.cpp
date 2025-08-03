#include <cstring>
#include <libxdb/process.hpp>
#include <libxdb/watchpoint.hpp>

namespace {

auto get_next_id() {
    static xdb::watchpoint::id_type next_id = 1;
    return next_id++;
}

}  // namespace

namespace xdb {

watchpoint::watchpoint(process& proc, virt_addr address, stoppoint_mode mode, std::size_t size)
    : process_(&proc), address_(address), mode_(mode), size_(size), is_enabled_(false) {
    // Check address alignment
    if ((address.addr() & (size - 1)) != 0) {
        xdb::error::send("Watchpoint address must be aligned to size");
    }
    id_ = get_next_id();
    record_data_change();
}

void watchpoint::enable() {
    if (!is_enabled_) {
        hardware_register_index_ = process_->set_hardware_stoppoint_(address_, mode_, size_);
        is_enabled_ = true;
    }
}

void watchpoint::disable() {
    if (is_enabled_) {
        process_->clear_hardware_stoppoint_(hardware_register_index_);
        is_enabled_ = false;
    }
}

void watchpoint::record_data_change() {
    std::uint64_t new_data = 0;
    auto read = process_->read_memory(address_, size_);
    std::memcpy(&new_data, read.data(), size_);
    previous_data_ = data_;
    data_ = new_data;
}

}  // namespace xdb
