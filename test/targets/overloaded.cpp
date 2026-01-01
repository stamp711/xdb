#include <iostream>
#include <string>

void print_type(int /*unused*/) { std::cout << "int"; }

void print_type(double /*unused*/) { std::cout << "double"; }

void print_type(std::string /*unused*/) { std::cout << "string"; }  // NOLINT

auto main() -> int {
    print_type(42);
    print_type(3.14);
    print_type("hello");
    return 0;
}
