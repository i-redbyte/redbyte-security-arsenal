#include <stdio.h>
#include <string.h>
#include <security_analyzer.h>
#include <hash_table.h>
#include "../macho-analyzer/include/macho_printer.h"
#include "../macho-analyzer/include/language_detector.h"
#include "../macho-analyzer/include/lc_commands.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [options] <mach-o file or --LC_COMMAND>\n", argv[0]);
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

    const char *lang = russian_language ? "ru" : "en";

    if (list_lc_commands) {
        print_all_lc_commands(lang);
        return 0;
    }

    if (lc_command) {
        const LCCommandInfo *info = get_lc_command_info(lc_command);
        if (info) {
            print_lc_command_info(info, lang);
        } else {
            printf(russian_language ? "Команда %s не найдена.\n" : "Command %s not found.\n", lc_command);
        }
        return 0;
    }

    if (!filename) {
        fprintf(stderr, russian_language ? "Не указан файл Mach-O.\n" : "No Mach-O file specified.\n");
        return 1;
    }

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror(russian_language ? "Не удалось открыть файл" : "Failed to open file");
        return 1;
    }

    MachOFile mach_o_file;
    if (analyze_mach_o(file, &mach_o_file) != 0) {
        fprintf(stderr, russian_language ? "Не удалось проанализировать файл Mach-O.\n" : "Failed to analyze Mach-O file.\n");
        fclose(file);
        return 1;
    }

    if (mach_o_file.commands) {
        if (list_dylibs) {
            print_dynamic_libraries(&mach_o_file);
        } else {
            print_mach_o_info(&mach_o_file, file);
        }

        analyze_section_permissions(&mach_o_file, file);
        analyze_debug_symbols(&mach_o_file, file);
        HashTable *unsafe_function_table = initialize_unsafe_function_table();
        if (!unsafe_function_table) {
            fprintf(stderr, "Failed to initialize unsafe function table\n");
            fclose(file);
            return 1;
        }

        if (analyze_unsafe_functions(&mach_o_file, file, unsafe_function_table) != 0) {
            fprintf(stderr, "Error analyzing unsafe functions\n");
        }

        hash_table_destroy(unsafe_function_table, NULL);
        LanguageInfo lang_info;
        if (detect_language_and_compiler(&mach_o_file, file, &lang_info) == 0) {
            printf(russian_language ? "Информация о языке и компиляторе:\n" : "Language and Compiler Information:\n");
            printf("  %s: %s\n", russian_language ? "Язык" : "Language", lang_info.language);
            printf("  %s: %s\n", russian_language ? "Компилятор" : "Compiler", lang_info.compiler);
            printf("\n");
        } else {
            printf(russian_language ? "Не удалось определить информацию о языке и компиляторе.\n" : "Failed to detect language and compiler information.\n");
        }
        free_mach_o_file(&mach_o_file);
    }
    fclose(file);
    return 0;
}
