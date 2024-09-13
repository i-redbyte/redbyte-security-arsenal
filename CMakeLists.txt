cmake_minimum_required(VERSION 3.10)
project(mac-security C)

set(CMAKE_C_STANDARD 11)

# Добавляем поддиректорию macho-analyzer
add_subdirectory(macho-analyzer)

# Добавляем исполняемый файл
add_executable(mac-security src/main.c)

# Указываем, что нужно линковать с библиотекой macho-analyzer
target_link_libraries(mac-security PRIVATE macho-analyzer)
target_include_directories(mac-security PRIVATE macho-analyzer/include)
