#ifndef MACHO_ANALYZER_H
#define MACHO_ANALYZER_H

#include <stdio.h>
#include <stdint.h>
#include <mach-o/loader.h>

typedef struct {
    char segname[17];  // имя сегмента (16 байт + '\0')
    uint64_t vmaddr;   // виртуальный адрес начала
    uint64_t vmsize;   // размер в памяти
    uint64_t fileoff;  // смещение в файле
    uint64_t filesize; // размер в файле
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;

    // Секции в этом сегменте
    struct section_64 *sections;
    struct section *sections32;
} Segment;

typedef struct {
    union {
        struct mach_header header32;
        struct mach_header_64 header64;
    } header;
    int is_64_bit;
    struct load_command *commands;
    uint32_t command_count;

    // Заголовок
    uint32_t magic;
    uint32_t cpu_type;
    uint32_t cpu_subtype;
    uint32_t file_type;
    uint32_t flags;

    // Команды загрузки
    uint32_t load_command_count;
    struct load_command *load_commands;

    // Сегменты
    uint32_t segment_count;
    Segment *segments;

    // Dylibs
    uint32_t linked_dylib_count;
    char **linked_dylibs;
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
 * Освобождает ресурсы, выделенные для хранения данных MachOFile.
 *
 * @param mach_o_file Структура с данными о Mach-O, для которой необходимо освободить память.
 */
void free_mach_o_file(MachOFile *mach_o_file);

const char *get_arch_name(cpu_type_t cpu, cpu_subtype_t sub);
int analyze_load_commands(FILE *file, MachOFile *mach_o_file);

#endif // MACHO_ANALYZER_H
