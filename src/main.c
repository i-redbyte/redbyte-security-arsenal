#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <mach-o/fat.h>
#include <libkern/OSByteOrder.h>

#include "../macho-analyzer/include/macho_printer.h"
#include "../macho-analyzer/include/language_detector.h"

#define MAX_ARCHS 8
#define MAX_FILE_SIZE (1L << 30) // 1 ГБ

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Использование: %s <файл Mach-O>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Ошибка: Не удалось открыть файл %s\n", filename);
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    if (file_size < sizeof(uint32_t)) {
        fprintf(stderr, "Ошибка: Файл слишком мал для Mach-O\n");
        fclose(file);
        return 1;
    }
    if (file_size > MAX_FILE_SIZE) {
        fprintf(stderr, "Ошибка: Файл слишком велик (%ld байт, максимум %ld)\n", file_size, MAX_FILE_SIZE);
        fclose(file);
        return 1;
    }
    rewind(file);

    uint32_t magic = 0;
    if (fread(&magic, sizeof(uint32_t), 1, file) != 1) {
        fprintf(stderr, "Ошибка: Не удалось прочитать magic number\n");
        fclose(file);
        return 1;
    }
    rewind(file);

    MachOFile first_arch = {0};
    bool first_arch_initialized = false;

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        struct fat_header fh;
        if (fread(&fh, sizeof(struct fat_header), 1, file) != 1) {
            fprintf(stderr, "Ошибка: Не удалось прочитать заголовок FAT\n");
            fclose(file);
            return 1;
        }

        uint32_t narch = OSSwapBigToHostInt32(fh.nfat_arch);
        printf("FAT бинарник с %u архитектурами:\n\n", narch);

        if (narch > MAX_ARCHS) {
            fprintf(stderr, "Ошибка: Слишком много архитектур: %u (максимум %d)\n", narch, MAX_ARCHS);
            fclose(file);
            return 1;
        }

        struct fat_arch archs[MAX_ARCHS];
        if (fread(archs, sizeof(struct fat_arch), narch, file) != narch) {
            fprintf(stderr, "Ошибка: Не удалось прочитать архитектуры FAT\n");
            fclose(file);
            return 1;
        }

        for (uint32_t i = 0; i < narch; i++) {
            uint32_t offset = OSSwapBigToHostInt32(archs[i].offset);
            if (fseek(file, offset, SEEK_SET) != 0) {
                fprintf(stderr, "Ошибка: Не удалось переместиться к смещению %u для архитектуры %u\n", offset, i + 1);
                continue;
            }

            MachOFile mf = {0};
            printf("---- Архитектура %u (смещение: %u) ----\n", i + 1, offset);

            if (analyze_mach_o(file, &mf) == 0) {
                printf("После analyze_mach_o: magic=0x%x, cputype=0x%x, ncmds=%u\n",
                       mf.magic, mf.cpu_type, mf.load_command_count);

                print_mach_o_info(&mf, file);

                if (!first_arch_initialized) {
                    first_arch = mf;
                    mf.commands = NULL;
                    mf.segments = NULL;
                    mf.dylibs = NULL;
                    first_arch_initialized = true;
                }
            } else {
                fprintf(stderr, "Ошибка: Не удалось проанализировать архитектуру %u\n", i + 1);
            }

            if (!first_arch_initialized || &mf != &first_arch) {
                free_mach_o_file(&mf);
            }

            printf("\n");
        }
    } else {
        MachOFile mf = {0};
        if (analyze_mach_o(file, &mf) == 0) {
            printf("После analyze_mach_o: magic=0x%x, cputype=0x%x, ncmds=%u\n",
                   mf.magic, mf.cpu_type, mf.load_command_count);

            print_mach_o_info(&mf, file);

            first_arch = mf;
            mf.commands = NULL;
            mf.segments = NULL;
            mf.dylibs = NULL;
            first_arch_initialized = true;
        } else {
            fprintf(stderr, "Ошибка: Не удалось проанализировать файл Mach-O\n");
            free_mach_o_file(&mf);
        }
    }

    if (first_arch_initialized) {
        LanguageInfo info = {0};
        if (detect_language_and_compiler(&first_arch, file, &info) == 0) {
            printf("Язык программирования: %s\n", info.language && info.language[0] ? info.language : "Неизвестно");
            printf("Компилятор: %s\n", info.compiler && info.compiler[0] ? info.compiler : "Неизвестно");
        } else {
            printf("Не удалось определить язык или компилятор.\n");
        }
        free_mach_o_file(&first_arch);
    }

    fclose(file);
    return 0;
}
