#ifndef MACHO_ANALYZER_H
#define MACHO_ANALYZER_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <mach-o/loader.h>

// Структура для хранения информации о сегменте
typedef struct {
    char segname[17];  // Имя сегмента (16 байт + '\0')
    uint64_t vmaddr;   // Виртуальный адрес начала
    uint64_t vmsize;   // Размер в памяти
    uint64_t fileoff;  // Смещение в файле
    uint64_t filesize; // Размер в файле
    uint32_t maxprot;  // Максимальные права доступа
    uint32_t initprot; // Начальные права доступа
    uint32_t nsects;   // Количество секций
    uint32_t flags;    // Флаги сегмента
    struct section_64 *sections; // Для 64-битных файлов
    struct section *sections32;  // Для 32-битных файлов
} Segment;

// Структура для хранения информации о динамической библиотеке
typedef struct {
    char *name;        // Имя библиотеки
    uint32_t timestamp; // Временная метка
    uint32_t current_version; // Текущая версия
    uint32_t compatibility_version; // Версия совместимости
} Dylib;

// Основная структура для хранения данных Mach-O файла
typedef struct {
    // Заголовок Mach-O
    uint32_t magic;           // Magic number (например, MH_MAGIC_64)
    cpu_type_t cpu_type;      // Тип процессора (например, CPU_TYPE_X86_64)
    cpu_subtype_t cpu_subtype;// Подтип процессора
    uint32_t file_type;       // Тип файла (например, MH_EXECUTE)
    uint32_t flags;           // Флаги (например, MH_PIE)
    uint32_t header_size;     // Размер заголовка
    bool is_64_bit;           // Флаг 64-битности
    union {
        struct mach_header header32;
        struct mach_header_64 header64;
    } header;

    // Команды загрузки
    uint32_t load_command_count; // Количество команд загрузки
    uint32_t sizeofcmds;         // Общий размер команд загрузки
    struct load_command *commands;// Массив команд загрузки

    // Сегменты
    uint32_t segment_count;      // Количество сегментов
    Segment *segments;           // Массив сегментов

    // Динамические библиотеки
    uint32_t dylib_count;        // Количество связанных библиотек
    Dylib *dylibs;               // Массив библиотек
} MachOFile;

/**
 * Анализирует Mach-O файл и сохраняет результат в структуру MachOFile.
 *
 * @param file Указатель на файл для анализа.
 * @param mach_o_file Структура для хранения данных о Mach-O.
 * @return 0 при успехе, -1 в случае ошибки.
 */
int analyze_mach_o(FILE *file, MachOFile *mach_o_file);

/**
 * Анализирует команды загрузки Mach-O файла.
 *
 * @param file Указатель на файл.
 * @param mach_o_file Структура с данными о Mach-O.
 * @return 0 при успехе, -1 в случае ошибки.
 */
int analyze_load_commands(FILE *file, MachOFile *mach_o_file);

/**
 * Освобождает ресурсы, выделенные для хранения данных MachOFile.
 *
 * @param mach_o_file Структура с данными о Mach-O.
 */
void free_mach_o_file(MachOFile *mach_o_file);

/**
 * Возвращает строковое представление архитектуры.
 *
 * @param cpu Тип процессора.
 * @param sub Подтип процессора.
 * @return Строковое имя архитектуры.
 */
const char *get_arch_name(cpu_type_t cpu, cpu_subtype_t sub);

#endif // MACHO_ANALYZER_H