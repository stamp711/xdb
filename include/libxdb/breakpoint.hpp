#pragma once

#include <cstdint>
#include <filesystem>
#include <libxdb/breakpoint_site.hpp>
#include <libxdb/stoppoint_collection.hpp>
#include <libxdb/types.hpp>
#include <string_view>
#include <utility>

namespace xdb {

class target;  // fwd

/// Base class for source-level breakpoints which may correspond to multiple breakpoint sites.
class breakpoint {
   public:
    virtual ~breakpoint() = default;

    breakpoint() = delete;

    breakpoint(breakpoint&&) = default;
    auto operator=(breakpoint&&) -> breakpoint& = default;

    breakpoint(const breakpoint&) = delete;
    auto operator=(const breakpoint&) = delete;

    using id_type = int32_t;
    auto id() const -> id_type { return id_; }

    void enable();
    void disable();

    auto is_enabled() const -> bool { return is_enabled_; }
    auto is_hardware() const -> bool { return is_hardware_; }
    auto is_internal() const -> bool { return is_internal_; }

    /// Resolve the breakpoint by creating breakpoint sites.
    /// When new shared library is loaded, make sure to resolve the breakpoint again.
    ///
    /// TODO: Correctly handle when multiple breakpoints has same resolved breakpoint site address
    virtual void resolve() = 0;

    auto breakpoint_sites() -> auto& { return breakpoint_sites_; }
    auto breakpoint_sites() const -> const auto& { return breakpoint_sites_; }

    auto at_address(virt_addr va) const -> bool { return breakpoint_sites_.contains_address(va); }
    auto in_range(virt_addr low, virt_addr high) const -> bool {
        return !breakpoint_sites_.get_in_address_range(low, high).empty();
    }

   protected:
    friend target;
    breakpoint(target& tgt, bool is_hardware = false, bool is_internal = false);

    id_type id_;
    target* target_;
    bool is_enabled_ = false;
    bool is_hardware_ = false;
    bool is_internal_ = false;

    stoppoint_collection<breakpoint_site, /*Owning=*/false> breakpoint_sites_;

    /// Each breakpoint has its own breakpoint_site id space. This specifies the next site id to use.
    breakpoint_site::id_type next_site_id_ = 1;
};

class function_breakpoint : public breakpoint {
   public:
    void resolve() override;
    auto function_name() const -> std::string_view { return function_name_; }

   private:
    friend target;
    function_breakpoint(target& tgt, std::string function_name, bool is_hardware = false, bool is_internal = false)
        : breakpoint(tgt, is_hardware, is_internal), function_name_(std::move(function_name)) {
        resolve();
    }

    std::string function_name_;
};

class line_breakpoint : public breakpoint {
   public:
    void resolve() override;
    auto file() const -> std::filesystem::path { return file_; }
    auto line() const -> std::size_t { return line_; }

   private:
    friend target;
    line_breakpoint(target& tgt, std::filesystem::path file, std::size_t line, bool is_hardware = false,
                    bool is_internal = false)
        : breakpoint(tgt, is_hardware, is_internal), file_(std::move(file)), line_(line) {
        resolve();
    }

    std::filesystem::path file_;
    std::size_t line_;
};

class address_breakpoint : public breakpoint {
   public:
    void resolve() override;
    auto address() const -> virt_addr { return address_; }

   private:
    friend target;
    address_breakpoint(target& tgt, virt_addr address, bool is_hardware = false, bool is_internal = false)
        : breakpoint(tgt, is_hardware, is_internal), address_(address) {
        resolve();
    }

    virt_addr address_;
};

}  // namespace xdb
