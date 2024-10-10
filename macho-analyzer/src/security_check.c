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
 * Основная функция для проверки всех защитных механизмов.
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 */
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
}
