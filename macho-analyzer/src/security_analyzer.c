#include "security_analyzer.h"
#include "macho_analyzer.h"
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

const UnsafeFunctionInfo unsafe_functions[] = {
        // Стандартные небезопасные функции C
        {"strcpy", "операция со строками", "высокая"},
        {"strncpy", "операция со строками", "средняя"},
        {"sprintf", "операция со строками", "высокая"},
        {"snprintf", "операция со строками", "средняя"},
        {"vsprintf", "операция со строками", "высокая"},
        {"vsnprintf", "операция со строками", "средняя"},
        {"gets", "операция ввода", "высокая"},
        {"fgets", "операция ввода", "средняя"},
        {"scanf", "операция ввода", "средняя"},
        {"sscanf", "операция ввода", "средняя"},
        {"strcat", "операция со строками", "средняя"},
        {"strncat", "операция со строками", "средняя"},

        // Работа с памятью
        {"memcpy", "операция с памятью", "средняя"},
        {"memmove", "операция с памятью", "средняя"},
        {"memset", "операция с памятью", "средняя"},
        {"bcopy", "операция с памятью", "высокая"},
        {"bzero", "операция с памятью", "высокая"},

        // Динамическое выделение памяти
        {"malloc", "выделение памяти", "низкая"},
        {"realloc", "выделение памяти", "низкая"},
        {"free", "освобождение памяти", "низкая"},
        {"calloc", "выделение памяти", "низкая"},

        // Функции работы со строками
        {"strdup", "выделение памяти", "средняя"},
        {"stpcpy", "операция со строками", "средняя"},
        {"strtok", "операция со строками", "низкая"},
        {"strncpy_s", "операция со строками", "низкая"},

        // Форматирование строк
        {"asprintf", "операция со строками", "средняя"},
        {"vasprintf", "операция со строками", "средняя"},

        // Работа с файлами
        {"fopen", "операция с файлами", "низкая"},
        {"fclose", "операция с файлами", "низкая"},
        {"fread", "операция с файлами", "средняя"},
        {"fwrite", "операция с файлами", "средняя"},

        // Динамическое выделение памяти
        {"alloca", "выделение памяти", "высокая"},
        {"valloc", "выделение памяти", "средняя"},
        {"posix_memalign", "выделение памяти", "низкая"},

        // Потокобезопасность
        {"rand", "генерация случайных чисел", "средняя"},
        {"srand", "генерация случайных чисел", "средняя"},
        {"drand48", "генерация случайных чисел", "средняя"},
        {"lrand48", "генерация случайных чисел", "средняя"},
        {"random", "генерация случайных чисел", "средняя"},

        // Опасные сетевые функции
        {"gethostbyname", "сетевая операция", "высокая"},
        {"gethostbyaddr", "сетевая операция", "высокая"},
        {"inet_ntoa", "сетевая операция", "средняя"},
        {"inet_aton", "сетевая операция", "средняя"},
        {"getaddrinfo", "сетевая операция", "средняя"},
        {"getnameinfo", "сетевая операция", "средняя"},

        // Управление процессами
        {"system", "выполнение процесса", "высокая"},
        {"popen", "выполнение процесса", "высокая"},
        {"exec", "выполнение процесса", "высокая"},
        {"execl", "выполнение процесса", "высокая"},
        {"execle", "выполнение процесса", "высокая"},
        {"execlp", "выполнение процесса", "высокая"},
        {"execv", "выполнение процесса", "высокая"},
        {"execvp", "выполнение процесса", "высокая"},
        {"execve", "выполнение процесса", "высокая"},

        // Потоки
        {"pthread_create", "управление потоками", "средняя"},
        {"pthread_exit", "управление потоками", "средняя"},
        {"pthread_cancel", "управление потоками", "средняя"},

        {NULL, NULL, NULL}  // Завершающий элемент массива
};

HashTable *initialize_unsafe_function_table(void) {
    HashTable *table = hash_table_create();
    if (!table) {
        fprintf(stderr, "Ошибка: Не удалось создать хеш-таблицу для небезопасных функций\n");
        return NULL;
    }
    for (int i = 0; unsafe_functions[i].function_name != NULL; i++) {
        hash_table_insert(table, unsafe_functions[i].function_name, (void *)&unsafe_functions[i]);
    }
    return table;
}

int analyze_unsafe_functions(const MachOFile *mach_o_file, FILE *file, HashTable *unsafe_function_table) {
    if (!mach_o_file || !file || !unsafe_function_table) {
        fprintf(stderr, "Ошибка: Неверные аргументы в analyze_unsafe_functions\n");
        return -1;
    }

    struct symtab_command *symtab_cmd = NULL;
    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->load_command_count; // Исправлено: command_count -> load_command_count

    // Поиск команды LC_SYMTAB
    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cmd;
            break;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    if (!symtab_cmd || symtab_cmd->nsyms == 0) {
        printf("Информация: Таблица символов отсутствует или пуста\n");
        return -1;
    }

    long current_offset = ftell(file);
    if (current_offset == -1) {
        fprintf(stderr, "Ошибка: Не удалось получить текущее смещение файла\n");
        return -1;
    }

    size_t symbol_size = mach_o_file->is_64_bit ? sizeof(struct nlist_64) : sizeof(struct nlist);
    void *symbols = malloc(symbol_size * symtab_cmd->nsyms);
    if (!symbols) {
        fprintf(stderr, "Ошибка: Не удалось выделить память для символов\n");
        return -1;
    }

    if (fseek(file, symtab_cmd->symoff, SEEK_SET) != 0) {
        fprintf(stderr, "Ошибка: Не удалось переместиться к таблице символов\n");
        free(symbols);
        return -1;
    }
    if (fread(symbols, symbol_size, symtab_cmd->nsyms, file) != symtab_cmd->nsyms) {
        fprintf(stderr, "Ошибка: Не удалось прочитать таблицу символов\n");
        free(symbols);
        fseek(file, current_offset, SEEK_SET);
        return -1;
    }

    char *string_table = malloc(symtab_cmd->strsize);
    if (!string_table) {
        fprintf(stderr, "Ошибка: Не удалось выделить память для таблицы строк\n");
        free(symbols);
        fseek(file, current_offset, SEEK_SET);
        return -1;
    }

    if (fseek(file, symtab_cmd->stroff, SEEK_SET) != 0) {
        fprintf(stderr, "Ошибка: Не удалось переместиться к таблице строк\n");
        free(symbols);
        free(string_table);
        fseek(file, current_offset, SEEK_SET);
        return -1;
    }
    if (fread(string_table, 1, symtab_cmd->strsize, file) != symtab_cmd->strsize) {
        fprintf(stderr, "Ошибка: Не удалось прочитать таблицу строк\n");
        free(symbols);
        free(string_table);
        fseek(file, current_offset, SEEK_SET);
        return -1;
    }

    int unsafe_function_count = 0;

    for (uint32_t i = 0; i < symtab_cmd->nsyms; i++) {
        char *sym_name;
        uint32_t strx;
        if (mach_o_file->is_64_bit) {
            struct nlist_64 *sym = &((struct nlist_64 *)symbols)[i];
            strx = sym->n_un.n_strx;
        } else {
            struct nlist *sym = &((struct nlist *)symbols)[i];
            strx = sym->n_un.n_strx;
        }

        if (strx >= symtab_cmd->strsize) {
            continue; // Пропускаем некорректные индексы
        }
        sym_name = string_table + strx;

        // Удаление префикса '_', если он присутствует
        if (sym_name[0] == '_') {
            sym_name++;
        }

        // Проверка наличия символа в хеш-таблице
        if (hash_table_contains(unsafe_function_table, sym_name)) {
            UnsafeFunctionInfo *info = (UnsafeFunctionInfo *)hash_table_get(unsafe_function_table, sym_name);
            printf("Предупреждение: Обнаружена небезопасная функция: %s\n", info->function_name);
            printf("  Категория: %s\n", info->category);
            printf("  Уровень опасности: %s\n", info->severity);
            unsafe_function_count++;
        }
    }

    free(symbols);
    free(string_table);
    fseek(file, current_offset, SEEK_SET);

    if (unsafe_function_count > 0) {
        printf("Всего обнаружено небезопасных функций: %d\n", unsafe_function_count);
    } else {
        printf("Небезопасные функции не обнаружены.\n");
    }

    return 0;
}

int analyze_section_permissions(const MachOFile *mach_o_file, FILE *file) {
    if (!mach_o_file || !file) {
        fprintf(stderr, "Ошибка: Неверные аргументы в analyze_section_permissions\n");
        return -1;
    }

    struct load_command *cmd = mach_o_file->commands;
    for (uint32_t i = 0; i < mach_o_file->load_command_count; i++) { // Исправлено: command_count -> load_command_count
        if (cmd->cmd == LC_SEGMENT || cmd->cmd == LC_SEGMENT_64) {
            uint32_t nsects;
            void *sections;

            if (cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg_cmd = (struct segment_command *)cmd;
                nsects = seg_cmd->nsects;
                sections = (struct section *)(seg_cmd + 1);
            } else {
                struct segment_command_64 *seg_cmd = (struct segment_command_64 *)cmd;
                nsects = seg_cmd->nsects;
                sections = (struct section_64 *)(seg_cmd + 1);
            }

            for (uint32_t j = 0; j < nsects; j++) {
                uint32_t flags;
                char sectname[17] = {0};
                if (cmd->cmd == LC_SEGMENT) {
                    struct section *section = &((struct section *)sections)[j];
                    flags = section->flags;
                    strncpy(sectname, section->sectname, 16);
                } else {
                    struct section_64 *section = &((struct section_64 *)sections)[j];
                    flags = section->flags;
                    strncpy(sectname, section->sectname, 16);
                }

                // Проверка на одновременную возможность записи и выполнения
                if ((flags & S_ATTR_PURE_INSTRUCTIONS) && (flags & S_ATTR_SOME_INSTRUCTIONS)) {
                    printf("Предупреждение: Секция %s имеет одновременно права на запись и выполнение\n", sectname);
                }
            }
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    return 0;
}

int analyze_debug_symbols(const MachOFile *mach_o_file, FILE *file) {
    if (!mach_o_file || !file) {
        fprintf(stderr, "Ошибка: Неверные аргументы в analyze_debug_symbols\n");
        return -1;
    }

    struct load_command *cmd = mach_o_file->commands;
    for (uint32_t i = 0; i < mach_o_file->load_command_count; i++) { // Исправлено: command_count -> load_command_count
        if (cmd->cmd == LC_SEGMENT || cmd->cmd == LC_SEGMENT_64) {
            uint32_t nsects;
            void *sections;

            if (cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg_cmd = (struct segment_command *)cmd;
                nsects = seg_cmd->nsects;
                sections = (struct section *)(seg_cmd + 1);
            } else {
                struct segment_command_64 *seg_cmd = (struct segment_command_64 *)cmd;
                nsects = seg_cmd->nsects;
                sections = (struct section_64 *)(seg_cmd + 1);
            }

            for (uint32_t j = 0; j < nsects; j++) {
                char sectname[17] = {0};
                if (cmd->cmd == LC_SEGMENT) {
                    struct section *section = &((struct section *)sections)[j];
                    strncpy(sectname, section->sectname, 16);
                } else {
                    struct section_64 *section = &((struct section_64 *)sections)[j];
                    strncpy(sectname, section->sectname, 16);
                }

                if (strcmp(sectname, "__debug_info") == 0 || strcmp(sectname, "__debug_line") == 0) {
                    printf("Обнаружены отладочные символы в секции %s\n", sectname);
                }
            }
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    return 0;
}