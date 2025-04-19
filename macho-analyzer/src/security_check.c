#include "security_check.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mach-o/nlist.h>

/**
 * Проверяет наличие ASLR (Address Space Layout Randomization).
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 * @return true, если ASLR поддерживается, false — если нет.
 */
static bool check_aslr(const MachOFile *mach_o_file) {
    if (!mach_o_file) {
        return false;
    }
    return (mach_o_file->is_64_bit
            ? (mach_o_file->header.header64.flags & MH_PIE) != 0
            : (mach_o_file->header.header32.flags & MH_PIE) != 0);
}

/**
 * Проверяет наличие DEP (Data Execution Prevention).
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 * @return true, если DEP поддерживается, false — если нет.
 */
static bool check_dep(const MachOFile *mach_o_file) {
    if (!mach_o_file) {
        return false;
    }
    return (mach_o_file->is_64_bit
            ? (mach_o_file->header.header64.flags & MH_NO_HEAP_EXECUTION) != 0
            : (mach_o_file->header.header32.flags & MH_NO_HEAP_EXECUTION) != 0);
}

/**
 * Проверяет наличие Stack Canaries.
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 * @param file Указатель на открытый файл Mach-O.
 * @return true, если Stack Canaries используются, false — если нет.
 */
static bool check_stack_canaries(const MachOFile *mach_o_file, FILE *file) {
    if (!mach_o_file || !mach_o_file->commands || !file) {
        fprintf(stderr, "Ошибка: Неверные аргументы в check_stack_canaries\n");
        return false;
    }

    struct load_command *cmd = mach_o_file->commands;
    struct symtab_command *symtab_cmd = NULL;

    for (uint32_t i = 0; i < mach_o_file->load_command_count; i++) { // Исправлено: command_count -> load_command_count
        if (cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cmd;
            break;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    if (!symtab_cmd || symtab_cmd->nsyms == 0) {
        return false; // Нет таблицы символов
    }

    long current_offset = ftell(file);
    if (current_offset == -1) {
        fprintf(stderr, "Ошибка: Не удалось получить текущее смещение файла\n");
        return false;
    }

    size_t symbol_size = mach_o_file->is_64_bit ? sizeof(struct nlist_64) : sizeof(struct nlist);
    void *symbols = malloc(symtab_cmd->nsyms * symbol_size);
    if (!symbols) {
        fprintf(stderr, "Ошибка: Не удалось выделить память для таблицы символов\n");
        return false;
    }

    if (fseek(file, symtab_cmd->symoff, SEEK_SET) != 0) {
        fprintf(stderr, "Ошибка: Не удалось переместиться к таблице символов\n");
        free(symbols);
        return false;
    }
    if (fread(symbols, symbol_size, symtab_cmd->nsyms, file) != symtab_cmd->nsyms) {
        fprintf(stderr, "Ошибка: Не удалось прочитать таблицу символов\n");
        free(symbols);
        fseek(file, current_offset, SEEK_SET);
        return false;
    }

    char *string_table = malloc(symtab_cmd->strsize);
    if (!string_table) {
        fprintf(stderr, "Ошибка: Не удалось выделить память для таблицы строк\n");
        free(symbols);
        fseek(file, current_offset, SEEK_SET);
        return false;
    }

    if (fseek(file, symtab_cmd->stroff, SEEK_SET) != 0) {
        fprintf(stderr, "Ошибка: Не удалось переместиться к таблице строк\n");
        free(symbols);
        free(string_table);
        fseek(file, current_offset, SEEK_SET);
        return false;
    }
    if (fread(string_table, 1, symtab_cmd->strsize, file) != symtab_cmd->strsize) {
        fprintf(stderr, "Ошибка: Не удалось прочитать таблицу строк\n");
        free(symbols);
        free(string_table);
        fseek(file, current_offset, SEEK_SET);
        return false;
    }

    bool found_stack_chk_fail = false;
    bool found_stack_chk_guard = false;

    for (uint32_t j = 0; j < symtab_cmd->nsyms; j++) {
        char *symbol_name;
        uint32_t strx;
        if (mach_o_file->is_64_bit) {
            struct nlist_64 *sym = &((struct nlist_64 *)symbols)[j];
            strx = sym->n_un.n_strx;
            if (strx >= symtab_cmd->strsize) continue;
            symbol_name = string_table + strx;
        } else {
            struct nlist *sym = &((struct nlist *)symbols)[j];
            strx = sym->n_un.n_strx;
            if (strx >= symtab_cmd->strsize) continue;
            symbol_name = string_table + strx;
        }

        if (strcmp(symbol_name, "__stack_chk_fail") == 0) {
            found_stack_chk_fail = true;
        } else if (strcmp(symbol_name, "__stack_chk_guard") == 0) {
            found_stack_chk_guard = true;
        }

        if (found_stack_chk_fail && found_stack_chk_guard) {
            break;
        }
    }

    free(symbols);
    free(string_table);
    fseek(file, current_offset, SEEK_SET);

    return found_stack_chk_fail && found_stack_chk_guard;
}

/**
 * Проверяет наличие sandbox и entitlements в Mach-O файле.
 * Ищет LC_CODE_SIGNATURE и LC_LOAD_DYLIB команды, которые могут указывать на использование песочницы.
 * Также проверяет наличие LC_SEGMENT и LC_SEGMENT_64 команд с секцией __TEXT,__entitlements.
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 */
void check_sandbox_and_entitlements(const MachOFile *mach_o_file) {
    if (!mach_o_file || !mach_o_file->commands) {
        fprintf(stderr, "Ошибка: Неверный Mach-O файл или отсутствуют команды\n");
        return;
    }

    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->load_command_count; // Исправлено: command_count -> load_command_count
    bool sandbox_found = false;
    bool entitlements_found = false;

    for (uint32_t i = 0; i < ncmds; i++) {
        switch (cmd->cmd) {
            case LC_LOAD_DYLIB: {
                struct dylib_command *dylib_cmd = (struct dylib_command *)cmd;
                if (dylib_cmd->dylib.name.offset >= cmd->cmdsize) {
                    break; // Пропускаем некорректное смещение
                }
                char *dylib_name = (char *)cmd + dylib_cmd->dylib.name.offset;
                if (strstr(dylib_name, "sandbox")) {
                    sandbox_found = true;
                    printf("Обнаружена песочница: %s\n", dylib_name);
                }
                break;
            }
            case LC_SEGMENT: {
                struct segment_command *seg_cmd = (struct segment_command *)cmd;
                if (strcmp(seg_cmd->segname, "__TEXT") == 0) {
                    struct section *sections = (struct section *)(seg_cmd + 1);
                    for (uint32_t j = 0; j < seg_cmd->nsects; j++) {
                        char sectname[17] = {0};
                        strncpy(sectname, sections[j].sectname, 16);
                        if (strcmp(sectname, "__entitlements") == 0) {
                            entitlements_found = true;
                            printf("Обнаружены полномочия в секции: %s\n", sectname);
                        }
                    }
                }
                break;
            }
            case LC_SEGMENT_64: {
                struct segment_command_64 *seg_cmd = (struct segment_command_64 *)cmd;
                if (strcmp(seg_cmd->segname, "__TEXT") == 0) {
                    struct section_64 *sections = (struct section_64 *)(seg_cmd + 1);
                    for (uint32_t j = 0; j < seg_cmd->nsects; j++) {
                        char sectname[17] = {0};
                        strncpy(sectname, sections[j].sectname, 16);
                        if (strcmp(sectname, "__entitlements") == 0) {
                            entitlements_found = true;
                            printf("Обнаружены полномочия в секции: %s\n", sectname);
                        }
                    }
                }
                break;
            }
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    if (!sandbox_found) {
        printf("Песочница не обнаружена в этом Mach-O файле.\n");
    }
    if (!entitlements_found) {
        printf("Полномочия не обнаружены в этом Mach-O файле.\n");
    }
}

/**
 * Проверяет наличие Bitcode в Mach-O файле.
 * Bitcode используется для обеспечения совместимости с различными архитектурами.
 * Проверяет наличие LC_DATA_IN_CODE команд.
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 * @return true, если Bitcode найден, иначе false.
 */
bool check_bitcode_presence(const MachOFile *mach_o_file) {
    if (!mach_o_file || !mach_o_file->commands) {
        fprintf(stderr, "Ошибка: Неверный Mach-O файл или отсутствуют команды\n");
        return false;
    }

    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->load_command_count; // Исправлено: command_count -> load_command_count

    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_DATA_IN_CODE) {
            return true;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }
    return false;
}

/**
 * Проверяет функции безопасности Mach-O файла.
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 * @param file Указатель на открытый файл Mach-O.
 */
void check_security_features(const MachOFile *mach_o_file, FILE *file) {
    if (!mach_o_file || !file) {
        printf("Ошибка: Неверный Mach-O файл или файл не открыт\n");
        return;
    }

    printf("Проверка функций безопасности:\n");

    // Проверка ASLR
    if (check_aslr(mach_o_file)) {
        printf("  ASLR: Поддерживается (установлен флаг PIE)\n");
    } else {
        printf("  ASLR: Не поддерживается (флаг PIE отсутствует)\n");
    }

    // Проверка DEP
    if (check_dep(mach_o_file)) {
        printf("  DEP: Поддерживается (отключено выполнение на куче)\n");
    } else {
        printf("  DEP: Не поддерживается\n");
    }

    // Проверка Stack Canaries
    if (check_stack_canaries(mach_o_file, file)) {
        printf("  Stack Canaries: Поддерживаются\n");
    } else {
        printf("  Stack Canaries: Не поддерживаются\n");
    }

    // Проверка Sandbox и Entitlements
    check_sandbox_and_entitlements(mach_o_file);

    // Проверка наличия Bitcode
    if (check_bitcode_presence(mach_o_file)) {
        printf("Обнаружен Bitcode в этом Mach-O файле.\n");
    } else {
        printf("Bitcode не обнаружен в этом Mach-O файле.\n");
    }
}