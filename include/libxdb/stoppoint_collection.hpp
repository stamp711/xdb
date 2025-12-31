#pragma once

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <libxdb/error.hpp>
#include <libxdb/types.hpp>
#include <memory>
#include <vector>

namespace xdb {

template <typename T>
concept StoppointLike = requires(const T t) {
    { t.id() } -> std::same_as<typename T::id_type>;
    { t.address() } -> std::same_as<virt_addr>;
    { t.is_enabled() } -> std::same_as<bool>;
} && requires(T t) {
    { t.disable() } -> std::same_as<void>;
} && std::equality_comparable<typename T::id_type>;

template <typename Stoppoint, bool Owning = true>
class stoppoint_collection {
   public:
    using pointer_type = std::conditional_t<Owning, std::unique_ptr<Stoppoint>, Stoppoint*>;

    auto push(pointer_type sp) -> Stoppoint& {
        stoppoints_.push_back(std::move(sp));
        return *stoppoints_.back();
    }

    auto contains_id(typename Stoppoint::id_type id) const -> bool { return find_by_id(id) != stoppoints_.end(); }

    auto contains_address(virt_addr address) const -> bool { return find_by_address(address) != stoppoints_.end(); }

    auto enabled_stoppoint_address(virt_addr address) const -> bool {
        auto it = find_by_address(address);
        return it != stoppoints_.end() && (*it)->is_enabled();
    }

    auto get_by_id(typename Stoppoint::id_type id) -> Stoppoint& { return get_by_id_impl(*this, id); }

    auto get_by_id(typename Stoppoint::id_type id) const -> const Stoppoint& { return get_by_id_impl(*this, id); }

    auto get_by_address(virt_addr address) -> Stoppoint& { return get_by_address_impl(*this, address); }

    auto get_by_address(virt_addr address) const -> const Stoppoint& { return get_by_address_impl(*this, address); }

    auto get_in_address_range(virt_addr start, virt_addr end) -> std::vector<Stoppoint*> {
        return get_in_address_range_impl(*this, start, end);
    }

    auto get_in_address_range(virt_addr start, virt_addr end) const -> std::vector<const Stoppoint*> {
        return get_in_address_range_impl(*this, start, end);
    }

    void remove_by_id(typename Stoppoint::id_type id) {
        auto it = find_by_id(id);
        if (it == stoppoints_.end()) {
            error::send("Stoppoint with id " + std::to_string(id) + " not found");
        }
        (*it)->disable();
        stoppoints_.erase(it);
    }

    void remove_by_address(virt_addr address) {
        auto it = find_by_address(address);
        if (it == stoppoints_.end()) {
            error::send("Stoppoint with address " + to_string(address) + " not found");
        }
        (*it)->disable();
        stoppoints_.erase(it);
    }

    template <typename F>
        requires std::invocable<F, Stoppoint&>
    void for_each(F f) {
        for (auto& stoppoint : stoppoints_) {
            f(*stoppoint);
        }
    }

    template <typename F>
        requires std::invocable<F, const Stoppoint&>
    void for_each(F f) const {
        for (const auto& stoppoint : stoppoints_) {
            f(*stoppoint);
        }
    }

    auto size() const -> std::size_t { return stoppoints_.size(); }
    auto empty() const -> bool { return stoppoints_.empty(); }

   private:
    using points_t = std::vector<pointer_type>;

    template <typename Collection>
    static auto get_by_id_impl(Collection& self, typename Stoppoint::id_type id) -> auto& {
        auto it = self.find_by_id(id);
        if (it == self.stoppoints_.end()) {
            error::send("Stoppoint with id " + std::to_string(id) + " not found");
        }
        return **it;
    }

    template <typename Collection>
    static auto get_by_address_impl(Collection& self, virt_addr address) -> auto& {
        auto it = self.find_by_address(address);
        if (it == self.stoppoints_.end()) {
            error::send("Stoppoint with address " + to_string(address) + " not found");
        }
        return **it;
    }

    template <typename Self>
    static auto get_in_address_range_impl(Self& self, virt_addr start, virt_addr end) {
        std::vector<std::conditional_t<std::is_const_v<std::remove_reference_t<Self>>, const Stoppoint*, Stoppoint*>>
            result;
        for (auto& stoppoint : self.stoppoints_) {
            if (stoppoint->in_range(start, end)) {
                result.emplace_back(&*stoppoint);
            }
        }
        return result;
    }

    template <typename Collection>
    static auto find_by_id_impl(Collection& self, typename Stoppoint::id_type id) {
        return std::find_if(self.stoppoints_.begin(), self.stoppoints_.end(),
                            [&](const auto& p) -> bool { return p->id() == id; });
    }
    auto find_by_id(typename Stoppoint::id_type id) -> typename points_t::iterator {
        return find_by_id_impl(*this, id);
    }
    auto find_by_id(typename Stoppoint::id_type id) const -> typename points_t::const_iterator {
        return find_by_id_impl(*this, id);
    }

    template <typename Collection>
    static auto find_by_address_impl(Collection& self, virt_addr address) {
        return std::find_if(self.stoppoints_.begin(), self.stoppoints_.end(),
                            [&](const auto& p) -> bool { return p->address() == address; });
    }
    auto find_by_address(virt_addr address) -> typename points_t::iterator {
        return find_by_address_impl(*this, address);
    }
    auto find_by_address(virt_addr address) const -> typename points_t::const_iterator {
        return find_by_address_impl(*this, address);
    }

    points_t stoppoints_;
};

}  // namespace xdb
