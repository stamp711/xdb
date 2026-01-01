#include <filesystem>

namespace xdb {

// Does path lhs ends in rhs? (e.g. /a/b/c and b/c)
auto path_ends_in(const std::filesystem::path& lhs, const std::filesystem::path& rhs) -> bool {
    auto size_lhs = std::distance(lhs.begin(), lhs.end());
    auto size_rhs = std::distance(rhs.begin(), rhs.end());
    if (size_rhs > size_lhs) return false;
    auto lhs_start = std::next(lhs.begin(), size_lhs - size_rhs);
    return std::equal(lhs_start, lhs.end(), rhs.begin());
}

}  // namespace xdb
