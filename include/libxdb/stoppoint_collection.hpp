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

template <StoppointLike Stoppoint>
class stoppoint_collection {
   public:
    Stoppoint& push(std::unique_ptr<Stoppoint> sp) {
        stoppoints_.push_back(std::move(sp));
        return *stoppoints_.back();
    }

    [[nodiscard]] bool contains_id(typename Stoppoint::id_type id) const {
        return find_by_id(id) != stoppoints_.end();
    }

    [[nodiscard]] bool contains_address(virt_addr address) const {
        return find_by_address(address) != stoppoints_.end();
    }

    [[nodiscard]] bool enabled_stoppoint_address(virt_addr address) const {
        auto it = find_by_address(address);
        return it != stoppoints_.end() && (*it)->is_enabled();
    }

    [[nodiscard]] Stoppoint& get_by_id(typename Stoppoint::id_type id) {
        return get_by_id_impl(*this, id);
    }

    [[nodiscard]] const Stoppoint& get_by_id(
        typename Stoppoint::id_type id) const {
        return get_by_id_impl(*this, id);
    }

    [[nodiscard]] Stoppoint& get_by_address(virt_addr address) {
        return get_by_address_impl(*this, address);
    }

    [[nodiscard]] const Stoppoint& get_by_address(virt_addr address) const {
        return get_by_address_impl(*this, address);
    }

    [[nodiscard]] std::vector<Stoppoint*> get_in_address_range(virt_addr start,
                                                               virt_addr end) {
        return get_in_address_range_impl(*this, start, end);
    }

    [[nodiscard]] std::vector<const Stoppoint*> get_in_address_range(
        virt_addr start, virt_addr end) const {
        return get_in_address_range_impl(*this, start, end);
    }

    void remove_by_id(typename Stoppoint::id_type id) {
        auto it = find_by_id(id);
        if (it == stoppoints_.end()) {
            error::send("Stoppoint with id " + std::to_string(id) +
                        " not found");
        }
        (*it)->disable();
        stoppoints_.erase(it);
    }

    void remove_by_address(virt_addr address) {
        auto it = find_by_address(address);
        if (it == stoppoints_.end()) {
            error::send("Stoppoint with address " + to_string(address) +
                        " not found");
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

    [[nodiscard]] std::size_t size() const { return stoppoints_.size(); }
    [[nodiscard]] bool empty() const { return stoppoints_.empty(); }

   private:
    using points_t = std::vector<std::unique_ptr<Stoppoint>>;

    template <typename Collection>
    [[nodiscard]] static auto& get_by_id_impl(Collection& self,
                                              typename Stoppoint::id_type id) {
        auto it = self.find_by_id(id);
        if (it == self.stoppoints_.end()) {
            error::send("Stoppoint with id " + std::to_string(id) +
                        " not found");
        }
        return **it;
    }

    template <typename Collection>
    [[nodiscard]] static auto& get_by_address_impl(Collection& self,
                                                   virt_addr address) {
        auto it = self.find_by_address(address);
        if (it == self.stoppoints_.end()) {
            error::send("Stoppoint with address " + to_string(address) +
                        " not found");
        }
        return **it;
    }

    template <typename Self>
    [[nodiscard]] static auto get_in_address_range_impl(Self& self,
                                                        virt_addr start,
                                                        virt_addr end) {
        std::vector<
            std::conditional_t<std::is_const_v<std::remove_reference_t<Self>>,
                               const Stoppoint*, Stoppoint*>>
            result;
        for (auto& stoppoint : self.stoppoints_) {
            if (stoppoint->in_range(start, end)) {
                result.emplace_back(stoppoint.get());
            }
        }
        return result;
    }

    template <typename Collection>
    static auto find_by_id_impl(Collection& self,
                                typename Stoppoint::id_type id) {
        return std::find_if(self.stoppoints_.begin(), self.stoppoints_.end(),
                            [&](const auto& p) { return p->id() == id; });
    }
    typename points_t::iterator find_by_id(typename Stoppoint::id_type id) {
        return find_by_id_impl(*this, id);
    }
    typename points_t::const_iterator find_by_id(
        typename Stoppoint::id_type id) const {
        return find_by_id_impl(*this, id);
    }

    template <typename Collection>
    static auto find_by_address_impl(Collection& self, virt_addr address) {
        return std::find_if(
            self.stoppoints_.begin(), self.stoppoints_.end(),
            [&](const auto& p) { return p->address() == address; });
    }
    typename points_t::iterator find_by_address(virt_addr address) {
        return find_by_address_impl(*this, address);
    }
    typename points_t::const_iterator find_by_address(virt_addr address) const {
        return find_by_address_impl(*this, address);
    }

    points_t stoppoints_;
};

}  // namespace xdb
