// Notes link: https://publish.obsidian.md/stamp711/01+Atomic/Exception+Frames

#pragma once

#include <cstddef>
#include <cstdint>
#include <libxdb/types.hpp>
#include <span>
#include <unordered_map>

namespace xdb {

class dwarf;

class call_frame_information {
   public:
    struct eh_hdr {
        const std::byte* start;
        const std::byte* search_table;
        size_t count;
        uint8_t encoding;
        call_frame_information* parent;

        /// Returns the pointer to the FDE that contains the given file_address.
        auto operator[](file_addr fa) const -> const std::byte*;
    };

    struct common_information_entry {
        uint32_t length;
        uint64_t code_alignment_factor;
        int64_t data_alignment_factor;
        bool fde_has_augmentation;
        uint8_t fde_pointer_encoding;
        std::span<const std::byte> instructions;
    };

    struct frame_description_entry {
        uint32_t length;
        const common_information_entry* cie;
        file_addr initial_location;
        uint64_t address_range;
        std::span<const std::byte> instructions;
    };

    call_frame_information() = delete;
    ~call_frame_information() = default;
    call_frame_information(call_frame_information&&) = delete;  // eh_hdr contains back pointer
    auto operator=(call_frame_information&&) -> call_frame_information& = delete;
    call_frame_information(const call_frame_information&) = delete;
    auto operator=(const call_frame_information&) -> call_frame_information& = delete;

    auto dwarf_info() const -> const dwarf& { return *dwarf_; }

    auto get_cie(file_offset foff) const -> const common_information_entry&;

   private:
    const dwarf* dwarf_;
    mutable std::unordered_map<uint64_t, common_information_entry> cie_map_;  // offset => cie entry cache
};

}  // namespace xdb
