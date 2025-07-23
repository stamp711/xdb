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

    bool contains_id(typename Stoppoint::id_type id) const {
        return find_by_id(id) != stoppoints_.end();
    }

    bool contains_address(virt_addr address) const {
        return find_by_address(address) != stoppoints_.end();
    }

    bool enabled_stoppoint_address(virt_addr address) const {
        auto it = find_by_address(address);
        return it != stoppoints_.end() && (*it)->is_enabled();
    }

    Stoppoint& get_by_id(typename Stoppoint::id_type id) {
        auto it = find_by_id(id);
        if (it == stoppoints_.end()) {
            error::send("Stoppoint with id " + std::to_string(id) +
                        " not found");
        }
        return **it;
    }

    const Stoppoint& get_by_id(typename Stoppoint::id_type id) const {
        return const_cast<stoppoint_collection*>(this)->get_by_id(id);
    }

    Stoppoint& get_by_address(virt_addr address) {
        auto it = find_by_address(address);
        if (it == stoppoints_.end()) {
            error::send("Stoppoint with address " + to_string(address) +
                        " not found");
        }
        return **it;
    }

    const Stoppoint& get_by_address(virt_addr address) const {
        return const_cast<stoppoint_collection*>(this)->get_by_address(address);
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

    std::size_t size() const { return stoppoints_.size(); }
    bool empty() const { return stoppoints_.empty(); }

   private:
    using points_t = std::vector<std::unique_ptr<Stoppoint>>;

    typename points_t::iterator find_by_id(typename Stoppoint::id_type id) {
        return std::find_if(stoppoints_.begin(), stoppoints_.end(),
                            [&](const auto& p) { return p->id() == id; });
    }
    typename points_t::const_iterator find_by_id(
        typename Stoppoint::id_type id) const {
        return const_cast<stoppoint_collection*>(this)->find_by_id(id);
    }
    typename points_t::iterator find_by_address(virt_addr address) {
        return std::find_if(
            stoppoints_.begin(), stoppoints_.end(),
            [&](const auto& p) { return p->address() == address; });
    }
    typename points_t::const_iterator find_by_address(virt_addr address) const {
        return const_cast<stoppoint_collection*>(this)->find_by_address(
            address);
    }

    points_t stoppoints_;
};

}  // namespace xdb
