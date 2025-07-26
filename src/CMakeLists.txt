file(GLOB SRC_FILES "*.cpp")
add_library(libxdb ${SRC_FILES})
add_library(xdb::libxdb ALIAS libxdb)

set_target_properties(
    libxdb
    PROPERTIES
        OUTPUT_NAME
            xdb # avoid liblibxdb.a name
)

target_compile_features(libxdb PUBLIC cxx_std_20)

target_link_libraries(libxdb PRIVATE Zydis::Zydis)

target_include_directories(
    libxdb
    PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PUBLIC
        $<INSTALL_INTERFACE::${CMAKE_INSTALL_INCLUDEDIR}>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

include(GNUInstallDirs)

install(
    TARGETS libxdb
    EXPORT xdb-targets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Install the header files
install(
    DIRECTORY ${PROJECT_SOURCE_DIR}/include
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    EXPORT xdb-targets
    FILE xdb-config.cmake
    NAMESPACE xdb::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/xdb
)
