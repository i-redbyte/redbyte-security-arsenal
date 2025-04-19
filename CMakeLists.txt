cmake_minimum_required(VERSION 3.19)
project(red_byte-security-arsenal C)

set(CMAKE_C_STANDARD 11)

enable_testing()

add_subdirectory(libs/hash_table)
add_subdirectory(macho-analyzer)

find_package(Curses REQUIRED)
include_directories(${CURSES_INCLUDE_DIR})

set(SOURCES
        src/main.c
        )

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE macho-analyzer ${CURSES_LIBRARIES})
target_include_directories(${PROJECT_NAME} PRIVATE macho-analyzer/include)

add_subdirectory(tests)
