cmake_minimum_required(VERSION 3.19)

project(hash_table C)

add_library(hash_table STATIC hash_table.c)

target_include_directories(hash_table PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set_target_properties(hash_table PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED ON
        )

target_compile_options(hash_table PRIVATE
        -Wall -Wextra -pedantic -Werror
        )

enable_testing()
add_subdirectory(tests)