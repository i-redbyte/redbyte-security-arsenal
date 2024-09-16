#include <stdio.h>
#include "../macho-analyzer/include/macho_analyzer.h"

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

    if (mach_o_file.commands) {
        print_mach_o_info(&mach_o_file, file);
        free_mach_o_file(&mach_o_file);
    }

    fclose(file);
    return 0;
}
