#include "security_analyzer.h"
#include "macho_analyzer.h"
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

const UnsafeFunctionInfo unsafe_functions[] = {
        // Стандартные небезопасные функции C
        {"strcpy", "string operation", "high"},
        {"strncpy", "string operation", "medium"},
        {"sprintf", "string operation", "high"},
        {"snprintf", "string operation", "medium"},
        {"vsprintf", "string operation", "high"},
        {"vsnprintf", "string operation", "medium"},
        {"gets", "input operation", "high"},
        {"fgets", "input operation", "medium"},
        {"scanf", "input operation", "medium"},
        {"sscanf", "input operation", "medium"},
        {"strcat", "string operation", "medium"},
        {"strncat", "string operation", "medium"},

        // Работа с памятью
        {"memcpy", "memory operation", "medium"},
        {"memmove", "memory operation", "medium"},
        {"memset", "memory operation", "medium"},
        {"bcopy", "memory operation", "high"},
        {"bzero", "memory operation", "high"},

        // Динамическое выделение памяти
        {"malloc", "memory allocation", "low"},
        {"realloc", "memory allocation", "low"},
        {"free", "memory deallocation", "low"},
        {"calloc", "memory allocation", "low"},

        // Функции работы со строками
        {"strdup", "memory allocation", "medium"},
        {"stpcpy", "string operation", "medium"},
        {"strtok", "string operation", "low"},
        {"strncpy_s", "string operation", "low"},

        // Форматирование строк
        {"asprintf", "string operation", "medium"},
        {"vasprintf", "string operation", "medium"},

        // Работа с файлами
        {"fopen", "file operation", "low"},
        {"fclose", "file operation", "low"},
        {"fread", "file operation", "medium"},
        {"fwrite", "file operation", "medium"},

        // Динамическое выделение памяти
        {"alloca", "memory allocation", "high"},
        {"valloc", "memory allocation", "medium"},
        {"posix_memalign", "memory allocation", "low"},

        // Потокобезопасность
        {"rand", "random generation", "medium"},
        {"srand", "random generation", "medium"},
        {"drand48", "random generation", "medium"},
        {"lrand48", "random generation", "medium"},
        {"random", "random generation", "medium"},

        // Опасные сетевые функции
        {"gethostbyname", "network operation", "high"},
        {"gethostbyaddr", "network operation", "high"},
        {"inet_ntoa", "network operation", "medium"},
        {"inet_aton", "network operation", "medium"},
        {"getaddrinfo", "network operation", "medium"},
        {"getnameinfo", "network operation", "medium"},

        // Управление процессами
        {"system", "process execution", "high"},
        {"popen", "process execution", "high"},
        {"exec", "process execution", "high"},
        {"execl", "process execution", "high"},
        {"execle", "process execution", "high"},
        {"execlp", "process execution", "high"},
        {"execv", "process execution", "high"},
        {"execvp", "process execution", "high"},
        {"execve", "process execution", "high"},

        // Потоки
        {"pthread_create", "thread management", "medium"},
        {"pthread_exit", "thread management", "medium"},
        {"pthread_cancel", "thread management", "medium"},

        {NULL, NULL, NULL}  // Завершающий элемент массива
};


int analyze_unsafe_functions(const MachOFile *mach_o_file, FILE *file) {
    struct symtab_command *symtab_cmd = NULL;
    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->command_count;

    // Поиск команды LC_SYMTAB
    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *) cmd;
            break;
        }
        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
    }

    if (!symtab_cmd || symtab_cmd->nsyms == 0) {
        return -1;
    }

    size_t symbol_size = mach_o_file->is_64_bit ? sizeof(struct nlist_64) : sizeof(struct nlist);
    void *symbols = malloc(symbol_size * symtab_cmd->nsyms);
    if (!symbols) {
        return -1;
    }

    fseek(file, symtab_cmd->symoff, SEEK_SET);
    if (fread(symbols, symbol_size, symtab_cmd->nsyms, file) != symtab_cmd->nsyms) {
        free(symbols);
        return -1;
    }

    char *string_table = malloc(symtab_cmd->strsize);
    if (!string_table) {
        free(symbols);
        return -1;
    }

    fseek(file, symtab_cmd->stroff, SEEK_SET);
    if (fread(string_table, 1, symtab_cmd->strsize, file) != symtab_cmd->strsize) {
        free(symbols);
        free(string_table);
        return -1;
    }

    int unsafe_function_count = 0;  // Счётчик небезопасных функций

    for (uint32_t i = 0; i < symtab_cmd->nsyms; i++) {
        char *sym_name;
        if (mach_o_file->is_64_bit) {
            struct nlist_64 *sym = &((struct nlist_64 *) symbols)[i];
            sym_name = string_table + sym->n_un.n_strx;
        } else {
            struct nlist *sym = &((struct nlist *) symbols)[i];
            sym_name = string_table + sym->n_un.n_strx;
        }

        // Проверка символа на небезопасные функции
        for (int j = 0; unsafe_functions[j].function_name != NULL; j++) {
            if (strstr(sym_name, unsafe_functions[j].function_name) != NULL) {
                printf("Warning: Detected use of unsafe function: %s\n", unsafe_functions[j].function_name);
                printf("  Category: %s\n", unsafe_functions[j].category);
                printf("  Severity: %s\n", unsafe_functions[j].severity);
                unsafe_function_count++;
            }
        }
    }

    free(symbols);
    free(string_table);

    if (unsafe_function_count > 0) {
        printf("Total unsafe functions detected: %d\n", unsafe_function_count);
    } else {
        printf("No unsafe functions detected.\n");
    }

    return 0;
}

int analyze_section_permissions(const MachOFile *mach_o_file, FILE *file) {
    struct load_command *cmd = mach_o_file->commands;

    for (uint32_t i = 0; i < mach_o_file->command_count; i++) {
        if (cmd->cmd == LC_SEGMENT || cmd->cmd == LC_SEGMENT_64) {
            uint32_t nsects;
            struct section *sections;

            if (cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg_cmd = (struct segment_command *) cmd;
                nsects = seg_cmd->nsects;
                sections = (struct section *) (seg_cmd + 1);
            } else {
                struct segment_command_64 *seg_cmd = (struct segment_command_64 *) cmd;
                nsects = seg_cmd->nsects;
                sections = (struct section *) (seg_cmd + 1);
            }

            for (uint32_t j = 0; j < nsects; j++) {
                if ((sections[j].flags & S_ATTR_PURE_INSTRUCTIONS) && (sections[j].flags & S_ATTR_SOME_INSTRUCTIONS)) {
                    printf("Warning: Section %s has both writable and executable permissions.\n", sections[j].sectname);
                }
            }
        }
        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
    }

    return 0;
}

int analyze_debug_symbols(const MachOFile *mach_o_file, FILE *file) {
    struct load_command *cmd = mach_o_file->commands;

    for (uint32_t i = 0; i < mach_o_file->command_count; i++) {
        if (cmd->cmd == LC_SEGMENT || cmd->cmd == LC_SEGMENT_64) {
            uint32_t nsects;
            struct section *sections;

            if (cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg_cmd = (struct segment_command *) cmd;
                nsects = seg_cmd->nsects;
                sections = (struct section *) (seg_cmd + 1);
            } else {
                struct segment_command_64 *seg_cmd = (struct segment_command_64 *) cmd;
                nsects = seg_cmd->nsects;
                sections = (struct section *) (seg_cmd + 1);
            }

            for (uint32_t j = 0; j < nsects; j++) {
                if (strcmp(sections[j].sectname, "__debug_info") == 0 || strcmp(sections[j].sectname, "__debug_line") == 0) {
                    printf("Detected debug symbols in section %s.\n", sections[j].sectname);
                }
            }
        }
        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
    }

    return 0;
}
