#ifndef MACHO_ANALYZER_H
#define MACHO_ANALYZER_H

#include <stdio.h>
#include <stdint.h>

// Структуры для хранения информации о Mach-O файле

typedef struct {
    uint32_t magic;
    int cputype;
    int cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
} MachHeader;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
} LoadCommand;

typedef struct {
    MachHeader header;
    LoadCommand *commands;
    uint32_t command_count;
} MachOFile;

// Анализирует Mach-O файл и заполняет структуру MachOFile
int analyze_mach_o(FILE *file, MachOFile *mach_o_file);

// Выводит информацию о Mach-O файле на экран
void print_mach_o_info(const MachOFile *mach_o_file);

// Освобождает выделенную память в структуре MachOFile
void free_mach_o_file(MachOFile *mach_o_file);

#endif // MACHO_ANALYZER_H
