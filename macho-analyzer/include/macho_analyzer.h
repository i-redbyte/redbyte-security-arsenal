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

// Анализирует Mach-O файл и заполняет структуру MachOFile
int analyze_mach_o(FILE *file, MachOFile *mach_o_file);

// Освобождает выделенную память в структуре MachOFile
void free_mach_o_file(MachOFile *mach_o_file);

void print_mach_o_info(const MachOFile *mach_o_file, FILE *file);

#endif // MACHO_ANALYZER_H
