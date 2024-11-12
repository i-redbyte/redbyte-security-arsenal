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
    return (mach_o_file->is_64_bit
            ? (mach_o_file->header.header64.flags & MH_NO_HEAP_EXECUTION) != 0
            : (mach_o_file->header.header32.flags & MH_NO_HEAP_EXECUTION) != 0);
}

/**
 * Проверяет наличие Stack Canaries.
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 * @return true, если Stack Canaries используются, false — если нет.
 */
static bool check_stack_canaries(const MachOFile *mach_o_file, FILE *file) {
    if (!mach_o_file->commands || !file) {
        return false;
    }

    struct load_command *cmd = mach_o_file->commands;
    struct symtab_command *symtab_cmd = NULL;

    for (uint32_t i = 0; i < mach_o_file->command_count; i++) {
        if (cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *) cmd;
            break;
        }
        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
    }

    if (!symtab_cmd) {
        return false;  // Нет таблицы символов
    }

    fseek(file, symtab_cmd->symoff, SEEK_SET);
    size_t symbol_size = mach_o_file->is_64_bit ? sizeof(struct nlist_64) : sizeof(struct nlist);
    void *symbols = malloc(symtab_cmd->nsyms * symbol_size);
    if (!symbols) {
        fprintf(stderr, "Failed to allocate memory for symbols.\n");
        return false;
    }

    if (fread(symbols, symbol_size, symtab_cmd->nsyms, file) != symtab_cmd->nsyms) {
        fprintf(stderr, "Failed to read symbol table.\n");
        free(symbols);
        return false;
    }

    fseek(file, symtab_cmd->stroff, SEEK_SET);
    char *string_table = malloc(symtab_cmd->strsize);
    if (!string_table) {
        fprintf(stderr, "Failed to allocate memory for string table.\n");
        free(symbols);
        return false;
    }

    if (fread(string_table, 1, symtab_cmd->strsize, file) != symtab_cmd->strsize) {
        fprintf(stderr, "Failed to read string table.\n");
        free(symbols);
        free(string_table);
        return false;
    }

    bool found_stack_chk_fail = false;
    bool found_stack_chk_guard = false;

    for (uint32_t j = 0; j < symtab_cmd->nsyms; j++) {
        if (mach_o_file->is_64_bit) {
            struct nlist_64 *sym = &((struct nlist_64 *) symbols)[j];
            char *symbol_name = string_table + sym->n_un.n_strx;
            if (strcmp(symbol_name, "__stack_chk_fail") == 0) {
                found_stack_chk_fail = true;
            }
            if (strcmp(symbol_name, "__stack_chk_guard") == 0) {
                found_stack_chk_guard = true;
            }
        } else {
            struct nlist *sym = &((struct nlist *) symbols)[j];
            char *symbol_name = string_table + sym->n_un.n_strx;
            if (strcmp(symbol_name, "__stack_chk_fail") == 0) {
                found_stack_chk_fail = true;
            }
            if (strcmp(symbol_name, "__stack_chk_guard") == 0) {
                found_stack_chk_guard = true;
            }
        }

        if (found_stack_chk_fail && found_stack_chk_guard) {
            break;
        }
    }
    free(symbols);
    free(string_table);

    return found_stack_chk_fail && found_stack_chk_guard;
}

/**
 * Функция для проверки наличия sandbox и entitlements в Mach-O файле.
 * Она ищет LC_CODE_SIGNATURE и LC_LOAD_DYLIB команды, которые могут указывать на использование песочницы.
 * Также проверяет наличие LC_SEGMENT и LC_SEGMENT_64 команд с секцией __TEXT,__entitlements.
 *
 * @param mach_o_file Структура MachOFile для хранения информации о файле.
 */
void check_sandbox_and_entitlements(const MachOFile *mach_o_file) {
    if (!mach_o_file || !mach_o_file->commands) {
        fprintf(stderr, "Invalid Mach-O file or no commands to process.\n");
        return;
    }

    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->command_count;
    int sandbox_found = 0;
    int entitlements_found = 0;

    // Итерируемся по командам загрузки для анализа наличия песочницы и entitlements
    for (uint32_t i = 0; i < ncmds; i++) {
        switch (cmd->cmd) {
            case LC_LOAD_DYLIB: {
                struct dylib_command *dylib_cmd = (struct dylib_command *)cmd;
                char *dylib_name = (char *)cmd + dylib_cmd->dylib.name.offset;

                // Если в списке библиотек упоминается песочница
                if (strstr(dylib_name, "sandbox")) {
                    sandbox_found = 1;
                    printf("Sandbox detected: %s\n", dylib_name);
                }
                break;
            }
            case LC_SEGMENT: {
                struct segment_command *seg_cmd = (struct segment_command *)cmd;
                if (strcmp(seg_cmd->segname, "__TEXT") == 0) {
                    struct section *sections = (struct section *)(seg_cmd + 1);
                    for (uint32_t j = 0; j < seg_cmd->nsects; j++) {
                        if (strcmp(sections[j].sectname, "__entitlements") == 0) {
                            entitlements_found = 1;
                            printf("Entitlements detected in section: %s\n", sections[j].sectname);
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
                        if (strcmp(sections[j].sectname, "__entitlements") == 0) {
                            entitlements_found = 1;
                            printf("Entitlements detected in section: %s\n", sections[j].sectname);
                        }
                    }
                }
                break;
            }
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    if (!sandbox_found) {
        printf("No Sandbox detected in this Mach-O file.\n");
    }

    if (!entitlements_found) {
        printf("No Entitlements detected in this Mach-O file.\n");
    }
}

void check_security_features(const MachOFile *mach_o_file, FILE *file) {
    if (!mach_o_file) {
        printf("Invalid Mach-O file.\n");
        return;
    }

    printf("Security Features Check:\n");

    // Проверка ASLR
    if (check_aslr(mach_o_file)) {
        printf("  ASLR: Supported (PIE flag is set)\n");
    } else {
        printf("  ASLR: Not supported (No PIE flag)\n");
    }

    // Проверка DEP
    if (check_dep(mach_o_file)) {
        printf("  DEP: Supported (No heap execution)\n");
    } else {
        printf("  DEP: Not supported\n");
    }

    // Проверка Stack Canaries
    if (check_stack_canaries(mach_o_file, file)) {
        printf("  Stack Canaries: Supported\n");
    } else {
        printf("  Stack Canaries: Not supported\n");
    }

    // Проверка Sandbox и Entitlements
    check_sandbox_and_entitlements(mach_o_file);
}
