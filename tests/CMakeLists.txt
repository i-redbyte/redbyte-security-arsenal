# tests/CMakeLists.txt
project(tests)

set(CMAKE_C_STANDARD 11)

# Tests for macho_analyzer
add_executable(macho_analyzer_tests ../macho-analyzer/src/macho_analyzer.c macho_analyzer_tests.c)
target_include_directories(macho_analyzer_tests PRIVATE ../macho-analyzer/include)
target_link_libraries(macho_analyzer_tests PRIVATE macho-analyzer)

add_test(NAME MachOAnalyzerTests COMMAND macho_analyzer_tests)