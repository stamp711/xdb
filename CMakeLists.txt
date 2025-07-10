cmake_minimum_required(VERSION 3.19)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(
    -Wall # Enable most warnings
    -Wextra # Enable even more warnings
    -Wpedantic # Warn about non-standard code
    -Wconversion # Implicit type conversions
    -Wsign-conversion # Signed/unsigned conversions
    -Wnull-dereference # Detect null pointer dereference
    -Wdouble-promotion # Warn float -> double promotion
    -Wshadow # Warn if variable shadows another
    # -Werror # Treat all warnings as errors (optional)
)

project("xdb" VERSION 0.1.0 LANGUAGES CXX ASM)

find_package(PkgConfig REQUIRED)
pkg_check_modules(libedit REQUIRED IMPORTED_TARGET libedit)

include(CTest)

add_subdirectory(src)
add_subdirectory(tools)

if(BUILD_TESTING)
    find_package(Catch2 CONFIG REQUIRED)
    add_subdirectory(test)
endif()
