function(add_test_cpp_target target_name)
    add_executable(${target_name} ${ARGN}) # All arguments after target_name are source files
    target_compile_options(${target_name} PRIVATE -g -O0)
    target_link_options(${target_name} PRIVATE -pie)
    add_dependencies(tests ${target_name})
endfunction()

function(add_test_asm_target target_name source_file)
    add_executable(${target_name} ${source_file})
    target_compile_options(${target_name} PRIVATE -g)
    target_link_options(${target_name} PRIVATE -pie)
    set_target_properties(${target_name} PROPERTIES LINKER_LANGUAGE C)
    add_dependencies(tests ${target_name})
endfunction()

add_test_cpp_target(hello hello.cpp)
add_test_cpp_target(run_endlessly run_endlessly.cpp)
add_test_cpp_target(end_immediately end_immediately.cpp)
add_test_asm_target(reg_write reg_write.s)
add_test_asm_target(reg_read reg_read.s)
add_test_cpp_target(memory memory.cpp)
add_test_cpp_target(anti_debugger anti_debugger.cpp)
add_test_cpp_target(multi_cu multi_cu_main.cpp multi_cu_other.cpp)

add_test_cpp_target(inlining inlining.cpp)
target_compile_options(
    inlining
    PRIVATE -O3 -fno-omit-frame-pointer -fno-optimize-sibling-calls
)

add_test_cpp_target(overloaded overloaded.cpp)
add_test_cpp_target(step step.cpp)
