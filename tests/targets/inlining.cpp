#include <cstdio>

__attribute__((always_inline)) inline void call_puts() { std::puts("Hello"); }

__attribute__((noinline)) auto leaf() { call_puts(); }

auto main() -> int {
    leaf();
    return 0;
}
