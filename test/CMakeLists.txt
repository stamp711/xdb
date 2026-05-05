add_executable(tests tests.cpp)
target_link_libraries(tests PRIVATE xdb::libxdb Catch2::Catch2WithMain)

include(Catch)
catch_discover_tests(tests)

add_subdirectory("targets")
