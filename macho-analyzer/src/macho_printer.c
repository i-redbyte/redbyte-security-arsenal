#include "macho_printer.h"
#include "macho_analyzer.h"
#include "security_check.h"
#include <stdlib.h>
#include <string.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>
#include <stdbool.h>

/**
 * Выводит информацию о заголовке Mach-O файла.
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 */
void print_header_info(const MachOFile *mach_o_file);

/**
 * Выводит информацию о команде сегмента.
 *
 * @param cmd Указатель на команду сегмента.
 * @param is_64_bit Флаг, указывающий, является ли файл 64-битным.
 */
static void print_segment_command(const struct load_command *cmd, bool is_64_bit);

/**
 * Выводит информацию о команде таблицы символов.
 *
 * @param cmd Указатель на команду таблицы символов.
 * @param mach_o_file Указатель на структуру MachOFile.
 * @param file Указатель на файл для чтения данных.
 */
static void print_symtab_command(const struct load_command *cmd, const MachOFile *mach_o_file, FILE *file);

/**
 * Выводит информацию о команде динамической таблицы символов.
 *
 * @param cmd Указатель на команду динамической таблицы символов.
 * @param file Указатель на файл для чтения данных.
 */
static void print_dysymtab_command(const struct load_command *cmd, FILE *file);

/**
 * Выводит информацию о команде динамической библиотеки.
 *
 * @param cmd Указатель на команду динамической библиотеки.
 */
static void print_dylib_command(const struct load_command *cmd);

/**
 * Выводит информацию о команде загрузчика динамических библиотек.
 *
 * @param cmd Указатель на команду загрузчика.
 */
void print_dylinker_command(const struct load_command *cmd);

/**
 * Выводит информацию о команде UUID.
 *
 * @param cmd Указатель на команду UUID.
 */
static void print_uuid_command(const struct load_command *cmd);

/**
 * Выводит информацию о команде минимальной версии.
 *
 * @param cmd Указатель на команду минимальной версии.
 */
static void print_version_min_command(const struct load_command *cmd);

/**
 * Выводит информацию о команде версии исходного кода.
 *
 * @param cmd Указатель на команду версии исходного кода.
 */
static void print_source_version_command(const struct load_command *cmd);

/**
 * Выводит информацию о команде точки входа.
 *
 * @param cmd Указатель на команду точки входа.
 */
static void print_entry_point_command(const struct load_command *cmd);

/**
 * Выводит информацию о команде начала функций.
 *
 * @param cmd Указатель на команду начала функций.
 * @param file Указатель на файл для чтения данных.
 */
static void print_function_starts_command(const struct load_command *cmd, FILE *file);

/**
 * Выводит информацию о команде данных в коде.
 *
 * @param cmd Указатель на команду данных в коде.
 */
static void print_data_in_code_command(const struct load_command *cmd);

/**
 * Выводит информацию о команде подписи кода.
 *
 * @param cmd Указатель на команду подписи кода.
 */
static void print_code_signature_command(const struct load_command *cmd);

/**
 * Выводит информацию о команде информации о шифровании.
 *
 * @param cmd Указатель на команду информации о шифровании.
 */
static void print_encryption_info_command(const struct load_command *cmd);

/**
 * Выводит информацию о команде пути загрузки.
 *
 * @param cmd Указатель на команду пути загрузки.
 */
static void print_rpath_command(const struct load_command *cmd);

/**
 * Выводит информацию о команде версии сборки.
 *
 * @param cmd Указатель на команду версии сборки.
 */
static void print_build_version_command(const struct load_command *cmd);

/**
 * Выводит информацию о команде опций компоновщика.
 *
 * @param cmd Указатель на команду опций компоновщика.
 */
static void print_linker_option_command(const struct load_command *cmd);

/**
 * Выводит информацию о команде заметок.
 *
 * @param cmd Указатель на команду заметок.
 */
static void print_note_command(const struct load_command *cmd);

/**
 * Выводит информацию о заголовке Mach-O файла.
 */
void print_header_info(const MachOFile *mach_o_file) {
    if (!mach_o_file) {
        fprintf(stderr, "Ошибка: NULL указатель на MachOFile\n");
        return;
    }

    printf("Заголовок Mach-O:\n");
    printf("  %s Mach-O файл\n", mach_o_file->is_64_bit ? "64-битный" : "32-битный");
    printf("  Magic: 0x%x\n", mach_o_file->magic);
    printf("  Тип процессора: 0x%x (%s)\n", mach_o_file->cpu_type, get_arch_name(mach_o_file->cpu_type, mach_o_file->cpu_subtype));
    printf("  Подтип процессора: 0x%x\n", mach_o_file->cpu_subtype);
    printf("  Тип файла: %u\n", mach_o_file->file_type);
    printf("  Количество команд: %u\n", mach_o_file->load_command_count);
    printf("  Размер команд: %u\n", mach_o_file->sizeofcmds);
    printf("  Флаги: 0x%x\n", mach_o_file->flags);
}

/**
 * Выводит информацию о команде сегмента.
 */
static void print_segment_command(const struct load_command *cmd, bool is_64_bit) {
    if (!cmd) {
        fprintf(stderr, "Ошибка: NULL указатель на команду сегмента\n");
        return;
    }

    if (is_64_bit) {
        struct segment_command_64 *seg_cmd = (struct segment_command_64 *)cmd;
        printf("  LC_SEGMENT_64\n");
        printf("  Имя сегмента: %s\n", seg_cmd->segname);
        printf("  Виртуальный адрес: 0x%llx\n", seg_cmd->vmaddr);
        printf("  Размер в памяти: 0x%llx\n", seg_cmd->vmsize);
        printf("  Смещение в файле: 0x%llx\n", seg_cmd->fileoff);
        printf("  Размер в файле: 0x%llx\n", seg_cmd->filesize);
        printf("  Максимальные права: 0x%x\n", seg_cmd->maxprot);
        printf("  Начальные права: 0x%x\n", seg_cmd->initprot);
        printf("  Количество секций: %u\n", seg_cmd->nsects);
        printf("  Флаги: 0x%x\n", seg_cmd->flags);
    } else {
        struct segment_command *seg_cmd = (struct segment_command *)cmd;
        printf("  LC_SEGMENT\n");
        printf("  Имя сегмента: %s\n", seg_cmd->segname);
        printf("  Виртуальный адрес: 0x%x\n", seg_cmd->vmaddr);
        printf("  Размер в памяти: 0x%x\n", seg_cmd->vmsize);
        printf("  Смещение в файле: 0x%x\n", seg_cmd->fileoff);
        printf("  Размер в файле: 0x%x\n", seg_cmd->filesize);
        printf("  Максимальные права: 0x%x\n", seg_cmd->maxprot);
        printf("  Начальные права: 0x%x\n", seg_cmd->initprot);
        printf("  Количество секций: %u\n", seg_cmd->nsects);
        printf("  Флаги: 0x%x\n", seg_cmd->flags);
    }
}

/**
 * Выводит информацию о команде таблицы символов.
 */
static void print_symtab_command(const struct load_command *cmd, const MachOFile *mach_o_file, FILE *file) {
    if (!cmd || !mach_o_file || !file) {
        fprintf(stderr, "Ошибка: Неверные аргументы в print_symtab_command\n");
        return;
    }

    struct symtab_command *symtab_cmd = (struct symtab_command *)cmd;
    printf("  LC_SYMTAB\n");
    printf("  Смещение таблицы символов: 0x%x\n", symtab_cmd->symoff);
    printf("  Количество символов: %u\n", symtab_cmd->nsyms);
    printf("  Смещение таблицы строк: 0x%x\n", symtab_cmd->stroff);
    printf("  Размер таблицы строк: %u\n", symtab_cmd->strsize);
}

/**
 * Выводит информацию о команде динамической таблицы символов.
 */
static void print_dysymtab_command(const struct load_command *cmd, FILE *file) {
    if (!cmd || !file) {
        fprintf(stderr, "Ошибка: Неверные аргументы в print_dysymtab_command\n");
        return;
    }

    struct dysymtab_command *dysymtab_cmd = (struct dysymtab_command *)cmd;
    printf("  LC_DYSYMTAB\n");
    printf("  Индекс локальных символов: %u\n", dysymtab_cmd->ilocalsym);
    printf("  Количество локальных символов: %u\n", dysymtab_cmd->nlocalsym);
    printf("  Индекс определённых внешних символов: %u\n", dysymtab_cmd->iextdefsym);
    printf("  Количество определённых внешних символов: %u\n", dysymtab_cmd->nextdefsym);
    printf("  Индекс неопределённых внешних символов: %u\n", dysymtab_cmd->iundefsym);
    printf("  Количество неопределённых внешних символов: %u\n", dysymtab_cmd->nundefsym);
}

/**
 * Выводит информацию о команде динамической библиотеки.
 */
static void print_dylib_command(const struct load_command *cmd) {
    if (!cmd) {
        fprintf(stderr, "Ошибка: NULL указатель на команду библиотеки\n");
        return;
    }

    struct dylib_command *dylib_cmd = (struct dylib_command *)cmd;
    char *name = (char *)cmd + dylib_cmd->dylib.name.offset;
    printf("  LC_%s\n", cmd->cmd == LC_LOAD_DYLIB ? "LOAD_DYLIB" :
                        cmd->cmd == LC_LOAD_WEAK_DYLIB ? "LOAD_WEAK_DYLIB" :
                        cmd->cmd == LC_REEXPORT_DYLIB ? "REEXPORT_DYLIB" :
                        "LOAD_UPWARD_DYLIB");
    printf("  Имя библиотеки: %s\n", name);
    printf("  Временная метка: %u\n", dylib_cmd->dylib.timestamp);
    printf("  Текущая версия: %u.%u.%u\n",
           dylib_cmd->dylib.current_version >> 16,
           (dylib_cmd->dylib.current_version >> 8) & 0xff,
           dylib_cmd->dylib.current_version & 0xff);
    printf("  Версия совместимости: %u.%u.%u\n",
           dylib_cmd->dylib.compatibility_version >> 16,
           (dylib_cmd->dylib.compatibility_version >> 8) & 0xff,
           dylib_cmd->dylib.compatibility_version & 0xff);
}

/**
 * Выводит информацию о команде загрузчика динамических библиотек.
 */
void print_dylinker_command(const struct load_command *cmd) {
    if (!cmd) {
        fprintf(stderr, "Ошибка: NULL указатель на команду загрузчика\n");
        return;
    }

    struct dylinker_command *dylinker_cmd = (struct dylinker_command *)cmd;
    char *name = (char *)cmd + dylinker_cmd->name.offset;
    printf("  LC_LOAD_DYLINKER\n");
    printf("  Имя загрузчика: %s\n", name);
}

/**
 * Выводит информацию о команде UUID.
 */
static void print_uuid_command(const struct load_command *cmd) {
    if (!cmd) {
        fprintf(stderr, "Ошибка: NULL указатель на команду UUID\n");
        return;
    }

    struct uuid_command *uuid_cmd = (struct uuid_command *)cmd;
    printf("  LC_UUID\n");
    printf("  UUID: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
           uuid_cmd->uuid[0], uuid_cmd->uuid[1], uuid_cmd->uuid[2], uuid_cmd->uuid[3],
           uuid_cmd->uuid[4], uuid_cmd->uuid[5], uuid_cmd->uuid[6], uuid_cmd->uuid[7],
           uuid_cmd->uuid[8], uuid_cmd->uuid[9], uuid_cmd->uuid[10], uuid_cmd->uuid[11],
           uuid_cmd->uuid[12], uuid_cmd->uuid[13], uuid_cmd->uuid[14], uuid_cmd->uuid[15]);
}

/**
 * Выводит информацию о команде минимальной версии.
 */
static void print_version_min_command(const struct load_command *cmd) {
    if (!cmd) {
        fprintf(stderr, "Ошибка: NULL указатель на команду минимальной версии\n");
        return;
    }

    struct version_min_command *version_cmd = (struct version_min_command *)cmd;
    printf("  LC_VERSION_MIN_%s\n",
           cmd->cmd == LC_VERSION_MIN_MACOSX ? "MACOSX" : "IPHONEOS");
    printf("  Версия: %u.%u\n", version_cmd->version >> 16, (version_cmd->version >> 8) & 0xff);
    printf("  SDK: %u.%u\n", version_cmd->sdk >> 16, (version_cmd->sdk >> 8) & 0xff);
}

/**
 * Выводит информацию о команде версии исходного кода.
 */
static void print_source_version_command(const struct load_command *cmd) {
    if (!cmd) {
        fprintf(stderr, "Ошибка: NULL указатель на команду версии исходного кода\n");
        return;
    }

    struct source_version_command *src_cmd = (struct source_version_command *)cmd;
    uint64_t version = src_cmd->version;
    printf("  LC_SOURCE_VERSION\n");
    printf("  Версия: %u.%u.%u.%u.%u\n",
           (uint32_t)((version >> 40) & 0xffffff),
           (uint32_t)((version >> 30) & 0x3ff),
           (uint32_t)((version >> 20) & 0x3ff),
           (uint32_t)((version >> 10) & 0x3ff),
           (uint32_t)(version & 0x3ff));
}

/**
 * Выводит информацию о команде точки входа.
 */
static void print_entry_point_command(const struct load_command *cmd) {
    if (!cmd) {
        fprintf(stderr, "Ошибка: NULL указатель на команду точки входа\n");
        return;
    }

    struct entry_point_command *entry_cmd = (struct entry_point_command *)cmd;
    printf("  LC_MAIN\n");
    printf("  Смещение точки входа: 0x%llx\n", entry_cmd->entryoff);
    printf("  Начальный размер стека: 0x%llx\n", entry_cmd->stacksize);
}

/**
 * Выводит информацию о команде начала функций.
 */
static void print_function_starts_command(const struct load_command *cmd, FILE *file) {
    if (!cmd || !file) {
        fprintf(stderr, "Ошибка: Неверные аргументы в print_function_starts_command\n");
        return;
    }

    struct linkedit_data_command *func_cmd = (struct linkedit_data_command *)cmd;
    printf("  LC_FUNCTION_STARTS\n");
    printf("  Смещение данных: 0x%x\n", func_cmd->dataoff);
    printf("  Размер данных: 0x%x\n", func_cmd->datasize);
}

/**
 * Выводит информацию о команде данных в коде.
 */
static void print_data_in_code_command(const struct load_command *cmd) {
    if (!cmd) {
        fprintf(stderr, "Ошибка: NULL указатель на команду данных в коде\n");
        return;
    }

    struct linkedit_data_command *data_cmd = (struct linkedit_data_command *)cmd;
    printf("  LC_DATA_IN_CODE\n");
    printf("  Смещение данных: 0x%x\n", data_cmd->dataoff);
    printf("  Размер данных: 0x%x\n", data_cmd->datasize);
}

/**
 * Выводит информацию о команде подписи кода.
 */
static void print_code_signature_command(const struct load_command *cmd) {
    if (!cmd) {
        fprintf(stderr, "Ошибка: NULL указатель на команду подписи кода\n");
        return;
    }

    struct linkedit_data_command *sig_cmd = (struct linkedit_data_command *)cmd;
    printf("  LC_CODE_SIGNATURE\n");
    printf("  Смещение данных: 0x%x\n", sig_cmd->dataoff);
    printf("  Размер данных: 0x%x\n", sig_cmd->datasize);
}

/**
 * Выводит информацию о команде информации о шифровании.
 */
static void print_encryption_info_command(const struct load_command *cmd) {
    if (!cmd) {
        fprintf(stderr, "Ошибка: NULL указатель на команду информации о шифровании\n");
        return;
    }

    struct encryption_info_command *enc_cmd = (struct encryption_info_command *)cmd;
    printf("  LC_ENCRYPTION_INFO%s\n", cmd->cmd == LC_ENCRYPTION_INFO_64 ? "_64" : "");
    printf("  Смещение шифрования: 0x%x\n", enc_cmd->cryptoff);
    printf("  Размер шифрования: 0x%x\n", enc_cmd->cryptsize);
    printf("  ID шифрования: %u\n", enc_cmd->cryptid);
}

/**
 * Выводит информацию о команде пути загрузки.
 */
static void print_rpath_command(const struct load_command *cmd) {
    if (!cmd) {
        fprintf(stderr, "Ошибка: NULL указатель на команду пути загрузки\n");
        return;
    }

    struct rpath_command *rpath_cmd = (struct rpath_command *)cmd;
    char *path = (char *)cmd + rpath_cmd->path.offset;
    printf("  LC_RPATH\n");
    printf("  Путь: %s\n", path);
}

/**
 * Выводит информацию о команде версии сборки.
 */
static void print_build_version_command(const struct load_command *cmd) {
    if (!cmd) {
        fprintf(stderr, "Ошибка: NULL указатель на команду версии сборки\n");
        return;
    }

    struct build_version_command *build_cmd = (struct build_version_command *)cmd;
    printf("  LC_BUILD_VERSION\n");
    printf("  Платформа: %u\n", build_cmd->platform);
    printf("  Минимальная версия ОС: %u.%u.%u\n",
           build_cmd->minos >> 16, (build_cmd->minos >> 8) & 0xff, build_cmd->minos & 0xff);
    printf("  Версия SDK: %u.%u.%u\n",
           build_cmd->sdk >> 16, (build_cmd->sdk >> 8) & 0xff, build_cmd->sdk & 0xff);
    printf("  Количество инструментов: %u\n", build_cmd->ntools);
}

/**
 * Выводит информацию о команде опций компоновщика.
 */
static void print_linker_option_command(const struct load_command *cmd) {
    if (!cmd) {
        fprintf(stderr, "Ошибка: NULL указатель на команду опций компоновщика\n");
        return;
    }

    struct linker_option_command *opt_cmd = (struct linker_option_command *)cmd;
    printf("  LC_LINKER_OPTION\n");
    printf("  Количество строк: %u\n", opt_cmd->count);
}

/**
 * Выводит информацию о команде заметок.
 */
static void print_note_command(const struct load_command *cmd) {
    if (!cmd) {
        fprintf(stderr, "Ошибка: NULL указатель на команду заметок\n");
        return;
    }

    struct note_command *note_cmd = (struct note_command *)cmd;
    printf("  LC_NOTE\n");
    printf("  Имя данных: %s\n", note_cmd->data_owner);
    printf("  Смещение данных: 0x%llx\n", note_cmd->offset);
    printf("  Размер данных: 0x%llx\n", note_cmd->size);
}

/**
 * Выводит информацию о Mach-O файле, включая заголовок, проверки безопасности и команды загрузки.
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 * @param file Указатель на файл для чтения дополнительных данных.
 */
void print_mach_o_info(const MachOFile *mach_o_file, FILE *file) {
    if (!mach_o_file) {
        fprintf(stderr, "Ошибка: NULL указатель на MachOFile\n");
        return;
    }

    print_header_info(mach_o_file);
    printf("===========================>ПРОВЕРКА БЕЗОПАСНОСТИ>=================================:\n");
    check_security_features(mach_o_file, file);
    printf("===========================<ПРОВЕРКА БЕЗОПАСНОСТИ<=================================:\n");
    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->load_command_count;

    for (uint32_t i = 0; i < ncmds; i++) {
        printf("Команда загрузки %d:\n", i + 1);
        printf("  Тип команды: %d\n", cmd->cmd);
        printf("  Размер команды: %d\n", cmd->cmdsize);

        switch (cmd->cmd) {
            case LC_SEGMENT:
            case LC_SEGMENT_64:
                print_segment_command(cmd, mach_o_file->is_64_bit);
                break;
            case LC_SYMTAB:
                print_symtab_command(cmd, mach_o_file, file);
                break;
            case LC_DYSYMTAB:
                print_dysymtab_command(cmd, file);
                break;
            case LC_LOAD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_REEXPORT_DYLIB:
            case LC_LOAD_UPWARD_DYLIB:
                print_dylib_command(cmd);
                break;
            case LC_LOAD_DYLINKER:
                print_dylinker_command(cmd);
                break;
            case LC_UUID:
                print_uuid_command(cmd);
                break;
            case LC_VERSION_MIN_MACOSX:
            case LC_VERSION_MIN_IPHONEOS:
                print_version_min_command(cmd);
                break;
            case LC_SOURCE_VERSION:
                print_source_version_command(cmd);
                break;
            case LC_MAIN:
                print_entry_point_command(cmd);
                break;
            case LC_FUNCTION_STARTS:
                print_function_starts_command(cmd, file);
                break;
            case LC_DATA_IN_CODE:
                print_data_in_code_command(cmd);
                break;
            case LC_CODE_SIGNATURE:
                print_code_signature_command(cmd);
                break;
            case LC_ENCRYPTION_INFO:
            case LC_ENCRYPTION_INFO_64:
                print_encryption_info_command(cmd);
                break;
            case LC_RPATH:
                print_rpath_command(cmd);
                break;
            case LC_BUILD_VERSION:
                print_build_version_command(cmd);
                break;
            case LC_LINKER_OPTION:
                print_linker_option_command(cmd);
                break;
            case LC_NOTE:
                print_note_command(cmd);
                break;
            default:
                printf("  Неизвестная или необработанная команда\n");
                break;
        }

        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
        printf("\n");
    }
}

/**
 * Выводит информацию о динамических библиотеках Mach-O файла.
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 */
void print_dynamic_libraries(const MachOFile *mach_o_file) {
    if (!mach_o_file || !mach_o_file->dylibs) {
        fprintf(stderr, "Ошибка: Нет данных о динамических библиотеках.\n");
        return;
    }

    printf("Динамические библиотеки:\n");
    for (uint32_t i = 0; i < mach_o_file->dylib_count; i++) {
        Dylib *dylib = &mach_o_file->dylibs[i];
        uint16_t current_major = (dylib->current_version >> 16) & 0xFFFF;
        uint8_t current_minor = (dylib->current_version >> 8) & 0xFF;
        uint8_t current_patch = dylib->current_version & 0xFF;
        uint16_t compat_major = (dylib->compatibility_version >> 16) & 0xFFFF;
        uint8_t compat_minor = (dylib->compatibility_version >> 8) & 0xFF;
        uint8_t compat_patch = dylib->compatibility_version & 0xFF;

        printf("  %s (Текущая версия: %u.%u.%u, Версия совместимости: %u.%u.%u)\n",
               dylib->name ? dylib->name : "<неизвестно>",
               current_major, current_minor, current_patch,
               compat_major, compat_minor, compat_patch);
    }
}