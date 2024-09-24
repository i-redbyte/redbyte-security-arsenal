#ifndef MACHO_ANALYZER_H
#define MACHO_ANALYZER_H

#include <stdio.h>
#include <stdint.h>
#include <mach-o/loader.h>

typedef struct {
    union {
        struct mach_header header32;
        struct mach_header_64 header64;
    } header;
    int is_64_bit;
    struct load_command *commands;
    uint32_t command_count;
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

#endif // MACHO_ANALYZER_H
