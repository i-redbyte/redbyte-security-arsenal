project(macho_analyzer C)

set(CMAKE_C_STANDARD 11)

set(SOURCES
        src/macho_analyzer.c
        src/macho_printer.c
        src/language_detector.c
        src/lc_commands.c
        src/security_analyzer.c
        src/hash_table.c
        )

add_library(macho-analyzer STATIC ${SOURCES})

target_include_directories(macho-analyzer PUBLIC include)
