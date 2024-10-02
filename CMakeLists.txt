cmake_minimum_required(VERSION 3.19)
project(mac-security C)

set(CMAKE_C_STANDARD 11)

add_subdirectory(macho-analyzer)

find_package(Curses REQUIRED)
include_directories(${CURSES_INCLUDE_DIR})

set(SOURCES
        src/main.c
        src/ui.c
        )
add_executable(mac-security ${SOURCES})
target_link_libraries(mac-security PRIVATE macho-analyzer ${CURSES_LIBRARIES})

target_include_directories(mac-security PRIVATE macho-analyzer/include)
