#include <cstdio>

__attribute__((always_inline)) inline void inline_inner() { std::puts("inline_inner"); }

__attribute__((always_inline)) inline void inline_outer() {
    inline_inner();
    std::puts("inline_outer");
}

__attribute__((noinline)) inline void noinline() {
    inline_outer();
    std::puts("noinline");
}

auto main() -> int {
    noinline();
    noinline();
    return 0;
}
