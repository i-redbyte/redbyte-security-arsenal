#include <stdio.h>
#include "../macho-analyzer/include/macho_analyzer.h"
#include "../macho-analyzer/include/macho_printer.h"
#include "../macho-analyzer/include/language_detector.h"
#include <string.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-l] <mach-o file>\n", argv[0]);
        return 1;
    }

    int list_dylibs = 0;
    const char *filename = NULL;

    // Парсинг аргументов командной строки
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            list_dylibs = 1;
        } else {
            filename = argv[i];
        }
    }

    if (!filename) {
        fprintf(stderr, "No Mach-O file specified.\n");
        return 1;
    }

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return 1;
    }

    MachOFile mach_o_file;
    if (analyze_mach_o(file, &mach_o_file) != 0) {
        fprintf(stderr, "Failed to analyze Mach-O file.\n");
        fclose(file);
        return 1;
    }

    if (mach_o_file.commands) {
        if (list_dylibs) {
            print_dynamic_libraries(&mach_o_file);
        } else {
            print_mach_o_info(&mach_o_file, file);
        }
        LanguageInfo lang_info;
        if (detect_language_and_compiler(&mach_o_file, (FILE *) file, &lang_info) == 0) {
            printf("Language and Compiler Information:\n");
            printf("  Language: %s\n", lang_info.language);
            printf("  Compiler: %s\n", lang_info.compiler);
            printf("\n");
        } else {
            printf("Failed to detect language and compiler information.\n");
        }
        free_mach_o_file(&mach_o_file);
    }

    fclose(file);
    return 0;
}
