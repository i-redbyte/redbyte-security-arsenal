#include "macho_printer.h"
#include "macho_analyzer.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

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

/**
 * Тест на корректный вывод заголовка 64-битного Mach-O файла
 */
void test_print_header_info_64_bit() {
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
    assert(strstr(buffer, "CPU Type: 16777223") != NULL);
    fclose(output);
}

/**
 * Тест на корректный вывод заголовка 32-битного Mach-O файла
 */
void test_print_header_info_32_bit() {
    MachOFile mock_file;
    mock_file.is_64_bit = 0;
    mock_file.header.header32.magic = 0xFEEDFACE;
    mock_file.header.header32.cputype = 7;  // CPU_TYPE_X86

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
    assert(strstr(buffer, "32-bit Mach-O File") != NULL);
    assert(strstr(buffer, "CPU Type: 7") != NULL);
    fclose(output);
}

/**
 * Тест на анализ команд загрузки (заглушка с тестовыми данными)
 */
void test_analyze_load_commands() {
    MachOFile mock_file;
    mock_file.is_64_bit = 1;
    mock_file.header.header64.ncmds = 2;
    mock_file.header.header64.sizeofcmds = sizeof(struct load_command) * 2;

    struct load_command *commands = malloc(sizeof(struct load_command) * 2);
    commands[0].cmd = LC_SEGMENT_64;
    commands[0].cmdsize = sizeof(struct load_command);
    commands[1].cmd = LC_SYMTAB;
    commands[1].cmdsize = sizeof(struct load_command);

    mock_file.commands = commands;
    mock_file.command_count = 2;

    FILE *output = freopen("output.txt", "w", stdout);
    if (!output) {
        perror("freopen failed");
        return;
    }

    print_mach_o_info(&mock_file, stdout);
    fflush(stdout);
    fclose(output);
    output = fopen("output.txt", "r");
    if (!output) {
        perror("fopen failed");
        return;
    }

    char buffer[1024];
    fread(buffer, sizeof(char), sizeof(buffer), output);
    assert(strstr(buffer, "Load Command 1:") != NULL);
    assert(strstr(buffer, "Load Command 2:") != NULL);
    assert(strstr(buffer, "LC_SEGMENT_64") != NULL);
    assert(strstr(buffer, "LC_SYMTAB") != NULL);

    free(commands);
    fclose(output);
}

/**
 * Тест на обработку ошибки при неверных данных
 */
void test_analyze_mach_o_invalid_data() {
    MachOFile mock_file;
    FILE *fake_file = fopen("fake_file.bin", "w+");
    if (!fake_file) {
        perror("fopen failed");
        return;
    }

    uint32_t bad_magic = 0xFFFFFFFF;
    fwrite(&bad_magic, sizeof(bad_magic), 1, fake_file);
    rewind(fake_file);

    int result = analyze_mach_o(fake_file, &mock_file);
    assert(result == -1);

    fclose(fake_file);
}

int main() {
    test_print_header_info();
    test_print_header_info_64_bit();
    test_print_header_info_32_bit();
    test_analyze_load_commands();
    test_analyze_mach_o_invalid_data();
    printf("All tests passed!\n");
    return 0;
}
