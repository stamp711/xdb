#include <cstdio>

__attribute__((always_inline)) inline void call_puts() { std::puts("Hello"); }

auto main() -> int { call_puts(); }
