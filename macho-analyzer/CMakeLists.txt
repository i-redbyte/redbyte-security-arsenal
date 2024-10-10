cmake_minimum_required(VERSION 3.19)

project(macho_analyzer C)

set(CMAKE_C_STANDARD 11)

set(SOURCES
        src/macho_analyzer.c
        src/macho_printer.c
        src/language_detector.c
        src/lc_commands.c
        src/security_analyzer.c
        src/security_check.c
        )

add_library(macho-analyzer STATIC ${SOURCES})

target_include_directories(macho-analyzer PUBLIC include)

target_link_libraries(macho-analyzer PUBLIC hash_table)