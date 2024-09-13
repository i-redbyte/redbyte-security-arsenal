project(macho-analyzer C)

set(CMAKE_C_STANDARD 11)

# Создаем статическую библиотеку macho-analyzer
add_library(macho-analyzer STATIC src/macho_analyzer.c)

# Указываем директорию с заголовочными файлами
target_include_directories(macho-analyzer PUBLIC include)
