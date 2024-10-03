#include "security_analyzer.h"
#include "macho_analyzer.h"
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Список известных небезопасных функций
const char *unsafe_functions[] = {
        // Стандартные небезопасные функции C
        "strcpy",      // Может привести к переполнению буфера
        "strncpy",     // Может привести к некорректному завершению строки
        "sprintf",     // Может привести к переполнению буфера
        "snprintf",    // Может привести к некорректному завершению строки
        "vsprintf",    // Может привести к переполнению буфера
        "vsnprintf",   // Может привести к некорректному завершению строки
        "gets",        // Чтение данных без ограничения длины
        "fgets",       // Потенциальная ошибка при неверном использовании
        "scanf",       // Форматирование строки может привести к ошибкам
        "sscanf",      // Форматирование строки может привести к ошибкам
        "strcat",      // Может привести к переполнению буфера
        "strncat",     // Может привести к некорректному завершению строки
        "memcpy",      // Может привести к переполнению буфера
        "memmove",     // Ошибки при копировании памяти
        "memset",      // Ошибки при работе с памятью
        "bcopy",       // Старый и небезопасный метод копирования памяти
        "bzero",       // Старый и небезопасный метод обнуления памяти
        "malloc",      // Ошибки при выделении памяти могут привести к уязвимостям
        "realloc",     // Ошибки при перераспределении памяти
        "free",        // Потенциальные ошибки двойного освобождения
        "calloc",      // Ошибки при выделении памяти могут привести к уязвимостям

        // Функции работы со строками
        "strdup",      // Может привести к утечке памяти
        "stpcpy",      // Может привести к переполнению буфера
        "strtok",      // Не потокобезопасная функция разбора строк
        "strncpy_s",   // Может привести к обрезанию строки

        // Форматирование строк
        "vsprintf",    // Форматирование строки без ограничения
        "asprintf",    // Может привести к переполнению буфера
        "vasprintf",   // Может привести к переполнению буфера

        // Работа с файлами
        "fopen",       // Не безопасна для использования без проверки ошибок
        "fclose",      // Ошибки при закрытии файлового дескриптора могут привести к утечкам
        "fread",       // Неправильное использование может привести к ошибкам
        "fwrite",      // Неправильное использование может привести к ошибкам

        // Динамическое выделение памяти
        "alloca",      // Может привести к переполнению стека
        "valloc",      // Может привести к проблемам при управлении памятью
        "posix_memalign", // Ошибки при неправильном выделении памяти

        // Потокобезопасность
        "rand",        // Не потокобезопасная генерация случайных чисел
        "srand",       // Использование устаревших методов генерации случайных чисел
        "drand48",     // Устаревший метод генерации случайных чисел
        "lrand48",     // Устаревший метод генерации случайных чисел
        "random",      // Устаревший метод генерации случайных чисел

        // Опасные сетевые функции
        "gethostbyname",   // Может вызвать переполнение буфера
        "gethostbyaddr",   // Может вызвать переполнение буфера
        "inet_ntoa",       // Не потокобезопасная функция преобразования IP адресов
        "inet_aton",       // Не потокобезопасная функция преобразования IP адресов
        "getaddrinfo",     // Неправильное использование может привести к утечкам памяти
        "getnameinfo",     // Неправильное использование может привести к утечкам памяти

        // Управление процессами
        "system",      // Использование может привести к выполнению вредоносного кода
        "popen",       // Может вызвать проблемы с безопасностью при использовании внешних процессов
        "exec",        // Может вызвать проблемы с безопасностью при использовании внешних процессов
        "execl",       // Может вызвать проблемы с безопасностью при использовании внешних процессов
        "execle",      // Может вызвать проблемы с безопасностью при использовании внешних процессов
        "execlp",      // Может вызвать проблемы с безопасностью при использовании внешних процессов
        "execv",       // Может вызвать проблемы с безопасностью при использовании внешних процессов
        "execvp",      // Может вызвать проблемы с безопасностью при использовании внешних процессов
        "execve",      // Может вызвать проблемы с безопасностью при использовании внешних процессов

        // Потоки
        "pthread_create",  // Неправильное использование может вызвать проблемы с управлением потоками
        "pthread_exit",    // Неправильное завершение потоков может привести к проблемам
        "pthread_cancel",  // Потенциально опасная функция для завершения потоков

        NULL
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

    for (uint32_t i = 0; i < symtab_cmd->nsyms; i++) {
        char *sym_name;
        if (mach_o_file->is_64_bit) {
            struct nlist_64 *sym = &((struct nlist_64 *) symbols)[i];
            sym_name = string_table + sym->n_un.n_strx;
        } else {
            struct nlist *sym = &((struct nlist *) symbols)[i];
            sym_name = string_table + sym->n_un.n_strx;
        }

        // Проверка на небезопасные функции
        for (int j = 0; unsafe_functions[j] != NULL; j++) {
            if (strstr(sym_name, unsafe_functions[j]) != NULL) {
                printf("Warning: Detected use of unsafe function: %s\n", sym_name);
            }
        }
    }

    free(symbols);
    free(string_table);
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
