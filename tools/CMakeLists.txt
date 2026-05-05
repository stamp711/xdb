find_package(magic_enum CONFIG REQUIRED)

file(GLOB COMMAND_HANDLER_SOURCES CONFIGURE_DEPENDS "command/*.cpp")
add_executable(xdb xdb.cpp ${COMMAND_HANDLER_SOURCES})
target_link_libraries(xdb PRIVATE xdb::libxdb PkgConfig::libedit fmt::fmt)

add_executable(dwarf_dump dwarf_dump.cpp)
target_link_libraries(dwarf_dump PRIVATE xdb::libxdb magic_enum::magic_enum)
