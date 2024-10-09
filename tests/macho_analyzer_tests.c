#include "macho_printer.h"
#include "macho_analyzer.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

void test_print_header_info() {
    MachOFile mock_file;
    mock_file.is_64_bit = 1;
    mock_file.header.header64.magic = 0xFEEDFACF;
    mock_file.header.header64.cputype = 16777223;

    FILE *output = freopen("output.txt", "w", stdout);
    if (!output) {
        perror("freopen failed");
        return;
    }

    print_header_info(&mock_file);
    fflush(stdout);
    fclose(output);
    output = fopen("output.txt", "r");
    if (!output) {
        perror("fopen failed");
        return;
    }

    char buffer[1024];
    fread(buffer, sizeof(char), sizeof(buffer), output);
    assert(strstr(buffer, "64-bit Mach-O File") != NULL);
    fclose(output);
}

int main() {
    test_print_header_info();
    printf("All tests passed!\n");
    return 0;
}
