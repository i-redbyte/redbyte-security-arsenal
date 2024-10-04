# tests/CMakeLists.txt
project(tests)

set(CMAKE_C_STANDARD 11)

add_executable(hash_table_tests ../macho-analyzer/src/hash_table.c hash_table_tests.c)
target_include_directories(hash_table_tests PRIVATE ../macho-analyzer/include)
target_link_libraries(hash_table_tests PRIVATE macho-analyzer)

add_test(NAME HashTableTests COMMAND hash_table_tests)
