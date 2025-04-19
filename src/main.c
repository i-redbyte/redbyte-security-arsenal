#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <mach-o/fat.h>
#include <mach/machine.h>
#include <libkern/OSByteOrder.h>
#include <unistd.h>

#include <security_analyzer.h>
#include "../macho-analyzer/include/macho_printer.h"
#include "../macho-analyzer/include/language_detector.h"
#include "../macho-analyzer/include/lc_commands.h"
#include "../macho-analyzer/include/macho_analyzer.h"

#define MAX_ARCHS 8

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Использование: %s [опции] <файл mach-o или --LC_КОМАНДА>\n", argv[0]);
        return 1;
    }

    int list_dylibs = 0;
    int list_lc_commands = 0;
    int russian_language = 0;
    const char *filename = NULL;
    const char *lc_command = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            list_dylibs = 1;
        } else if (strcasecmp(argv[i], "--ru") == 0) {
            russian_language = 1;
        } else if (strcasecmp(argv[i], "--llc") == 0) {
            list_lc_commands = 1;
        } else if (strncasecmp(argv[i], "--LC_", 5) == 0) {
            lc_command = argv[i] + 2;
        } else {
            filename = argv[i];
        }
    }

    Language lang = russian_language ? LANG_RU : LANG_EN;
    initialize_lc_command_table();

    if (list_lc_commands) {
        print_all_lc_commands(lang);
        return 0;
    }

    if (lc_command) {
        const LCCommandInfo *info = get_lc_command_info(lc_command);
        if (info) {
            print_lc_command_info(info, lang);
        } else {
            printf("Команда %s не найдена.\n", lc_command);
        }
        return 0;
    }

    if (!filename) {
        fprintf(stderr, "Не указан файл Mach-O.\n");
        return 1;
    }

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Не удалось открыть файл");
        return 1;
    }

    // Отладка: вывод первых 16 байт файла
    unsigned char buf[16];
    fread(buf, 1, 16, file);
    printf("[main.c] Первые 16 байт файла: ");
    for (int i = 0; i < 16; i++) printf("%02x ", buf[i]);
    printf("\n");
    rewind(file);

    uint32_t magic = 0;
    if (fread(&magic, sizeof(uint32_t), 1, file) != 1) {
        fprintf(stderr, "Не удалось прочитать magic\n");
        fclose(file);
        return 1;
    }
    fseek(file, 0, SEEK_SET);

    MachOFile main_arch_file;
    memset(&main_arch_file, 0, sizeof(MachOFile));
    bool main_arch_set = false;

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        struct fat_header fatHeader;
        fread(&fatHeader, sizeof(struct fat_header), 1, file);
        uint32_t nfat_arch = OSSwapBigToHostInt32(fatHeader.nfat_arch);
        printf("Fat-бинарник с %u архитектурами:\n\n", nfat_arch);

        struct fat_arch fatArchs[MAX_ARCHS];
        for (uint32_t i = 0; i < nfat_arch && i < MAX_ARCHS; i++) {
            fread(&fatArchs[i], sizeof(struct fat_arch), 1, file);
        }

        for (uint32_t i = 0; i < nfat_arch && i < MAX_ARCHS; i++) {
            uint32_t offset = OSSwapBigToHostInt32(fatArchs[i].offset);
            cpu_type_t cpuType = OSSwapBigToHostInt32(fatArchs[i].cputype);
            cpu_subtype_t cpuSubtype = OSSwapBigToHostInt32(fatArchs[i].cpusubtype);

            printf("---- Анализ архитектуры %u (%s) ----\n", i + 1, get_arch_name(cpuType, cpuSubtype));
            printf("Смещение = %u\n", offset);

            fseek(file, offset, SEEK_SET);

            MachOFile arch;
            memset(&arch, 0, sizeof(MachOFile));

            if (analyze_mach_o(file, &arch) != 0 || analyze_load_commands(file, &arch) != 0) {
                fprintf(stderr, "Не удалось проанализировать архитектуру %u.\n", i + 1);
                continue;
            }

            if (!main_arch_set) {
                memcpy(&main_arch_file, &arch, sizeof(MachOFile));
                main_arch_set = true;
            }

            if (list_dylibs) {
                print_dynamic_libraries(&arch);
            } else {
                print_mach_o_info(&arch, file);
            }

            analyze_section_permissions(&arch, file);
            analyze_debug_symbols(&arch, file);

            HashTable *table = initialize_unsafe_function_table();
            if (table) {
                analyze_unsafe_functions(&arch, file, table);
                hash_table_destroy(table, NULL);
            }

            free_mach_o_file(&arch);
        }
    } else {
        // Файл не FAT — обычный Mach-O
        fseek(file, 0, SEEK_SET);
        if (analyze_mach_o(file, &main_arch_file) != 0 || analyze_load_commands(file, &main_arch_file) != 0) {
            fprintf(stderr, "Не удалось проанализировать Mach-O файл.\n");
            fclose(file);
            return 1;
        }

        if (list_dylibs) {
            print_dynamic_libraries(&main_arch_file);
        } else {
            print_mach_o_info(&main_arch_file, file);
        }

        analyze_section_permissions(&main_arch_file, file);
        analyze_debug_symbols(&main_arch_file, file);

        HashTable *table = initialize_unsafe_function_table();
        if (table) {
            analyze_unsafe_functions(&main_arch_file, file, table);
            hash_table_destroy(table, NULL);
        }
        main_arch_set = true;
    }

    if (main_arch_set) {
        LanguageInfo lang_info;
        if (detect_language_and_compiler(&main_arch_file, file, &lang_info) == 0) {
            printf("\nИнформация о языке и компиляторе:\n");
            printf("  Язык: %s\n", lang_info.language);
            printf("  Компилятор: %s\n", lang_info.compiler);
        } else {
            printf("\nНе удалось определить язык или компилятор.\n");
        }
        free_mach_o_file(&main_arch_file);
    }

    fclose(file);
    return 0;
}