add_executable(xdb xdb.cpp)
target_link_libraries(xdb PRIVATE xdb::libxdb PkgConfig::libedit fmt::fmt)
