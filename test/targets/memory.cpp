#include <sys/signal.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <iostream>

namespace {
constexpr std::uint64_t TEST_VALUE = 0xcafecafe;
constexpr std::size_t BUFFER_SIZE = 128;
}  // namespace

int main() {
    std::uint64_t a = TEST_VALUE;
    auto* a_address = &a;

    ::write(STDOUT_FILENO, static_cast<const void*>(&a_address), sizeof(void*));
    ::fflush(stdout);

    raise(SIGTRAP);

    std::array<char, BUFFER_SIZE> b{};
    auto* b_address = &b;
    write(STDOUT_FILENO, static_cast<const void*>(&b_address), sizeof(void*));
    fflush(stdout);
    raise(SIGTRAP);

    std::cout << b.data();
}
