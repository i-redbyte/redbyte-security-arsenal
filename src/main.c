#include <stdio.h>
#include "../macho-analyzer/include/macho_analyzer.h"
#include "../macho-analyzer/include/macho_printer.h"
#include "../macho-analyzer/include/language_detector.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mach-o file>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
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
    LanguageInfo lang_info;
    if (detect_language_and_compiler(&mach_o_file, file, &lang_info) == 0) {
        printf("Language and Compiler Information:\n");
        printf("  Language: %s\n", lang_info.language);
        printf("  Compiler: %s\n", lang_info.compiler);
        printf("\n");
    } else {
        printf("Failed to detect language and compiler information.\n");
    }
    if (mach_o_file.commands) {
        print_mach_o_info(&mach_o_file, file);
        free_mach_o_file(&mach_o_file);
    }

    fclose(file);
    return 0;
}
