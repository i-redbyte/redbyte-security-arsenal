# tests/CMakeLists.txt
project(tests)

set(CMAKE_C_STANDARD 11)

# Tests for hash_table
add_executable(hash_table_tests ../macho-analyzer/src/hash_table.c hash_table_tests.c)
target_include_directories(hash_table_tests PRIVATE ../macho-analyzer/include)
target_link_libraries(hash_table_tests PRIVATE macho-analyzer)

add_test(NAME HashTableTests COMMAND hash_table_tests)

# Tests for macho_analyzer
add_executable(macho_analyzer_tests ../macho-analyzer/src/macho_analyzer.c macho_analyzer_tests.c)
target_include_directories(macho_analyzer_tests PRIVATE ../macho-analyzer/include)
target_link_libraries(macho_analyzer_tests PRIVATE macho-analyzer)

add_test(NAME MachOAnalyzerTests COMMAND macho_analyzer_tests)