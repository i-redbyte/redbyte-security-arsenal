cmake_minimum_required(VERSION 3.10)
project(mac-security C)

set(CMAKE_C_STANDARD 11)

add_subdirectory(macho-analyzer)

add_executable(mac-security src/main.c)

target_link_libraries(mac-security PRIVATE macho-analyzer)
target_include_directories(mac-security PRIVATE macho-analyzer/include)
