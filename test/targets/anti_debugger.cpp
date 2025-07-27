#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <numeric>

void f() { std::puts("Putting pineapple on pizza..."); }
void f_end() {}

int checksum() {
    const auto *const start = reinterpret_cast<volatile const char *>(&f);
    const auto *end = reinterpret_cast<volatile const char *>(&f_end);
    return std::accumulate(start, end, 0);
}

int main() {
    auto safe = checksum();

    auto *ptr = &f;
    ::write(STDOUT_FILENO, static_cast<const void *>(&ptr), sizeof(void *));
    std::fflush(stdout);

    std::raise(SIGTRAP);

    while (true) {
        if (checksum() == safe) {
            f();
        } else {
            std::puts("Putting pepperoni on pizza...");
        }

        std::fflush(stdout);
        std::raise(SIGTRAP);
    }

    return 0;
}
