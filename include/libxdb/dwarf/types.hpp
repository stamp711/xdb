#pragma once

#include <cstdint>
#include <vector>

namespace xdb {
struct attr_spec {
    uint64_t type;
    uint64_t form;
    int64_t implicit_const_value;  // For DW_FORM_implicit_const
};

struct abbrev {
    uint64_t code;
    uint64_t tag;
    bool has_children;
    std::vector<attr_spec> attrs;
};

}  // namespace xdb
