#include <filesystem>

namespace xdb {

// Does path lhs ends in rhs? (e.g. /a/b/c and b/c)
auto path_ends_in(const std::filesystem::path& lhs, const std::filesystem::path& rhs) -> bool {
    auto size_lhs = std::distance(lhs.begin(), lhs.end());
    auto size_rhs = std::distance(rhs.begin(), rhs.end());
    if (size_rhs > size_lhs) return false;
    auto rhs_start = std::next(rhs.begin(), size_lhs - size_rhs);
    return std::equal(rhs_start, rhs.end(), lhs.begin());
}

}  // namespace xdb
