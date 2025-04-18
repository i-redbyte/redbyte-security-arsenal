#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/fat.h>
#include <mach/machine.h>
#include <libkern/OSByteOrder.h>

#include <security_analyzer.h>
#include "../macho-analyzer/include/macho_printer.h"
#include "../macho-analyzer/include/language_detector.h"
#include "../macho-analyzer/include/lc_commands.h"

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

    uint32_t magic = 0;
    if (fread(&magic, sizeof(uint32_t), 1, file) != 1) {
        fprintf(stderr, "Не удалось прочитать magic число.\n");
        fclose(file);
        return 1;
    }
    rewind(file);

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        struct fat_header fatHeader;
        if (fread(&fatHeader, sizeof(struct fat_header), 1, file) != 1) {
            fprintf(stderr, "Ошибка при чтении заголовка fat-файла.\n");
            fclose(file);
            return 1;
        }

        uint32_t nfat_arch = OSSwapBigToHostInt32(fatHeader.nfat_arch);
        printf("Fat-бинарник с %u архитектурами:\n\n", nfat_arch);

        struct fat_arch *fatArchs = calloc(nfat_arch, sizeof(struct fat_arch));
        if (!fatArchs) {
            fprintf(stderr, "Ошибка выделения памяти.\n");
            fclose(file);
            return 1;
        }

        for (uint32_t i = 0; i < nfat_arch; i++) {
            if (fread(&fatArchs[i], sizeof(struct fat_arch), 1, file) != 1) {
                fprintf(stderr, "Ошибка чтения fat_arch %u.\n", i);
                free(fatArchs);
                fclose(file);
                return 1;
            }
        }

        for (uint32_t i = 0; i < nfat_arch; i++) {
            uint32_t offset = OSSwapBigToHostInt32(fatArchs[i].offset);
            uint32_t size = OSSwapBigToHostInt32(fatArchs[i].size);
            cpu_type_t cpuType = OSSwapBigToHostInt32(fatArchs[i].cputype);
            cpu_subtype_t cpuSubtype = OSSwapBigToHostInt32(fatArchs[i].cpusubtype);

            printf("---- Анализ архитектуры %u (%s) ----\n", i + 1, get_arch_name(cpuType, cpuSubtype));
            printf("Смещение = %u, Размер = %u\n", offset, size);

            if (fseek(file, offset, SEEK_SET) != 0) {
                fprintf(stderr, "Не удалось перейти к архитектуре %u.\n", i + 1);
                continue;
            }

            MachOFile arch_file;
            memset(&arch_file, 0, sizeof(MachOFile));

            if (analyze_mach_o(file, &arch_file) != 0) {
                fprintf(stderr, "Не удалось проанализировать архитектуру %u.\n", i + 1);
                continue;
            }

            if (analyze_load_commands(file, &arch_file) != 0) {
                fprintf(stderr, "Не удалось прочитать команды загрузки архитектуры %u.\n", i + 1);
                free_mach_o_file(&arch_file);
                continue;
            }

            if (list_dylibs) {
                print_dynamic_libraries(&arch_file);
            } else {
                print_mach_o_info(&arch_file, file);
            }

            analyze_section_permissions(&arch_file, file);
            analyze_debug_symbols(&arch_file, file);

            HashTable *unsafe_function_table = initialize_unsafe_function_table();
            if (unsafe_function_table) {
                analyze_unsafe_functions(&arch_file, file, unsafe_function_table);
                hash_table_destroy(unsafe_function_table, NULL);
            }

            LanguageInfo lang_info;
            if (detect_language_and_compiler(&arch_file, file, &lang_info) == 0) {
                printf("Информация о языке и компиляторе:\n");
                printf("  Язык: %s\n", lang_info.language);
                printf("  Компилятор: %s\n", lang_info.compiler);
                printf("\n");
            } else {
                printf("Не удалось определить язык или компилятор.\n");
            }

            free_mach_o_file(&arch_file);
        }

        free(fatArchs);
    } else {
        MachOFile mach_o_file;
        memset(&mach_o_file, 0, sizeof(MachOFile));

        if (analyze_mach_o(file, &mach_o_file) != 0) {
            fprintf(stderr, "Не удалось проанализировать файл Mach-O.\n");
            fclose(file);
            return 1;
        }

        if (analyze_load_commands(file, &mach_o_file) != 0) {
            fprintf(stderr, "Не удалось прочитать команды загрузки.\n");
            free_mach_o_file(&mach_o_file);
            fclose(file);
            return 1;
        }

        if (list_dylibs) {
            print_dynamic_libraries(&mach_o_file);
        } else {
            print_mach_o_info(&mach_o_file, file);
        }

        analyze_section_permissions(&mach_o_file, file);
        analyze_debug_symbols(&mach_o_file, file);

        HashTable *unsafe_function_table = initialize_unsafe_function_table();
        if (!unsafe_function_table) {
            fprintf(stderr, "Ошибка инициализации таблицы небезопасных функций\n");
            fclose(file);
            return 1;
        }

        analyze_unsafe_functions(&mach_o_file, file, unsafe_function_table);
        hash_table_destroy(unsafe_function_table, NULL);

        LanguageInfo lang_info;
        if (detect_language_and_compiler(&mach_o_file, file, &lang_info) == 0) {
            printf("Информация о языке и компиляторе:\n");
            printf("  Язык: %s\n", lang_info.language);
            printf("  Компилятор: %s\n", lang_info.compiler);
            printf("\n");
        } else {
            printf("Не удалось определить язык или компилятор.\n");
        }

        free_mach_o_file(&mach_o_file);
    }

    fclose(file);
    return 0;
}
