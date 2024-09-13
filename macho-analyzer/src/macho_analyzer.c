#include "macho_analyzer.h"
#include <stdlib.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/swap.h>

// Внутренние функции
static int analyze_mach_header(FILE *file, MachOFile *mach_o_file);
static int analyze_load_commands(FILE *file, MachOFile *mach_o_file);

int analyze_mach_o(FILE *file, MachOFile *mach_o_file) {
    if (!file || !mach_o_file) {
        return -1;
    }

    // Инициализируем структуру
    memset(mach_o_file, 0, sizeof(MachOFile));

    // Читаем магическое число
    uint32_t magic;
    if (fread(&magic, sizeof(uint32_t), 1, file) != 1) {
        return -1;
    }
    fseek(file, 0, SEEK_SET); // Возвращаемся в начало файла

    // Проверяем на Fat Binary
    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        // Для простоты предположим, что работаем только с одноархитектурными файлами
        fprintf(stderr, "Fat binaries не поддерживаются в данной версии.\n");
        return -1;
    } else {
        // Анализируем Mach-O файл
        if (analyze_mach_header(file, mach_o_file) != 0) {
            return -1;
        }
        if (analyze_load_commands(file, mach_o_file) != 0) {
            return -1;
        }
    }

    return 0;
}

static int analyze_mach_header(FILE *file, MachOFile *mach_o_file) {
    // Читаем заголовок
    uint32_t magic;
    fread(&magic, sizeof(uint32_t), 1, file);
    fseek(file, 0, SEEK_SET); // Возвращаемся в начало файла

    if (magic == MH_MAGIC_64) {
        struct mach_header_64 header;
        if (fread(&header, sizeof(struct mach_header_64), 1, file) != 1) {
            return -1;
        }

        mach_o_file->header.magic = header.magic;
        mach_o_file->header.cputype = header.cputype;
        mach_o_file->header.cpusubtype = header.cpusubtype & ~CPU_SUBTYPE_MASK;
        mach_o_file->header.filetype = header.filetype;
        mach_o_file->header.ncmds = header.ncmds;
        mach_o_file->header.sizeofcmds = header.sizeofcmds;
        mach_o_file->header.flags = header.flags;
    } else if (magic == MH_MAGIC) {
        struct mach_header header;
        if (fread(&header, sizeof(struct mach_header), 1, file) != 1) {
            return -1;
        }

        mach_o_file->header.magic = header.magic;
        mach_o_file->header.cputype = header.cputype;
        mach_o_file->header.cpusubtype = header.cpusubtype & ~CPU_SUBTYPE_MASK;
        mach_o_file->header.filetype = header.filetype;
        mach_o_file->header.ncmds = header.ncmds;
        mach_o_file->header.sizeofcmds = header.sizeofcmds;
        mach_o_file->header.flags = header.flags;
    } else {
        fprintf(stderr, "Unsupported file format or invalid magic number.\n");
        return -1;
    }

    return 0;
}

static int analyze_load_commands(FILE *file, MachOFile *mach_o_file) {
    // Позиция после заголовка
    long commands_offset = ftell(file);

    // Выделяем память для команд загрузки
    mach_o_file->commands = malloc(mach_o_file->header.sizeofcmds);
    if (!mach_o_file->commands) {
        return -1;
    }

    // Читаем команды загрузки
    if (fread(mach_o_file->commands, 1, mach_o_file->header.sizeofcmds, file) != mach_o_file->header.sizeofcmds) {
        free(mach_o_file->commands);
        return -1;
    }

    mach_o_file->command_count = mach_o_file->header.ncmds;

    return 0;
}

void print_mach_o_info(const MachOFile *mach_o_file) {
    if (!mach_o_file) {
        return;
    }

    printf("Mach-O Header:\n");
    printf("  Magic: 0x%x\n", mach_o_file->header.magic);
    printf("  CPU Type: %d\n", mach_o_file->header.cputype);
    printf("  CPU Subtype: %d\n", mach_o_file->header.cpusubtype);
    printf("  File Type: %d\n", mach_o_file->header.filetype);
    printf("  Number of Commands: %d\n", mach_o_file->header.ncmds);
    printf("  Size of Commands: %d\n", mach_o_file->header.sizeofcmds);
    printf("  Flags: 0x%x\n\n", mach_o_file->header.flags);

    struct load_command *cmd = mach_o_file->commands;
    for (uint32_t i = 0; i < mach_o_file->command_count; i++) {
        printf("Load Command %d:\n", i + 1);
        printf("  Command Type: %d\n", cmd->cmd);
        printf("  Command Size: %d\n", cmd->cmdsize);

        // Переходим к следующей команде загрузки
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
        printf("\n");
    }
}

void free_mach_o_file(MachOFile *mach_o_file) {
    if (mach_o_file && mach_o_file->commands) {
        free(mach_o_file->commands);
        mach_o_file->commands = NULL;
    }
}
