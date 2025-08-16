cmake_minimum_required(VERSION 3.19)

# Set vcpkg toolchain if VCPKG_ROOT is set and toolchain not already specified
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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
find_package(fmt CONFIG REQUIRED)
find_package(Zydis CONFIG REQUIRED)

include(CTest)

add_subdirectory(src)
add_subdirectory(tools)

if(BUILD_TESTING)
    find_package(Catch2 CONFIG REQUIRED)
    add_subdirectory(test)
endif()
