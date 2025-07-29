file(GLOB COMMAND_HANDLER_SOURCES "command/*.cpp")
add_executable(xdb xdb.cpp ${COMMAND_HANDLER_SOURCES})
target_link_libraries(xdb PRIVATE xdb::libxdb PkgConfig::libedit fmt::fmt)
