file(GLOB COMMAND_HANDLER_SOURCES "command/*.cpp")
add_executable(xdb xdb.cpp ${COMMAND_HANDLER_SOURCES})
target_link_libraries(xdb PRIVATE xdb::libxdb PkgConfig::libedit fmt::fmt)

add_executable(dwarf_dump dwarf_dump.cpp)
find_package(magic_enum CONFIG REQUIRED)
target_link_libraries(dwarf_dump PRIVATE xdb::libxdb)
target_link_libraries(dwarf_dump PRIVATE magic_enum::magic_enum)
