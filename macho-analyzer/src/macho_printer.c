#include "macho_printer.h"
#include "macho_analyzer.h"
#include "security_check.h"
#include <stdlib.h>
#include <string.h>
#include <mach-o/nlist.h>
#include <stdbool.h>

/**
 * Функция для декодирования ULEB128.
 * Декодирует значение в формате ULEB128, которое используется в некоторых командах Mach-O файлов.
 *
 * @param p Указатель на текущую позицию данных.
 * @param end Указатель на конец данных.
 * @return Декодированное значение.
 */
static uint64_t decode_uleb128(const uint8_t **p, const uint8_t *end);

/**
 * Функция для вывода команды сегмента.
 *
 * @param cmd Указатель на команду сегмента.
 * @param is_64_bit Флаг, указывающий, является ли файл 64-битным.
 */
static void print_segment_command(const struct load_command *cmd, bool is_64_bit);

/**
 * Функция для вывода команды символов.
 *
 * @param cmd Указатель на команду символов.
 * @param mach_o_file Указатель на структуру MachOFile.
 * @param file Указатель на файл для вывода информации.
 */
static void print_symtab_command(const struct load_command *cmd, const MachOFile *mach_o_file, FILE *file);

/**
 * Функция для вывода команды динамической таблицы символов.
 *
 * @param cmd Указатель на команду динамической таблицы символов.
 * @param file Указатель на файл для вывода информации.
 */
static void print_dysymtab_command(const struct load_command *cmd, FILE *file);

/**
 * Функция для вывода команды динамической библиотеки.
 *
 * @param cmd Указатель на команду динамической библиотеки.
 */
static void print_dylib_command(const struct load_command *cmd);

/**
 * Функция для вывода команды загрузчика динамических библиотек.
 *
 * @param cmd Указатель на команду загрузчика.
 */
static void print_dylinker_command(const struct load_command *cmd);

/**
 * Функция для вывода команды UUID.
 *
 * @param cmd Указатель на команду UUID.
 */
static void print_uuid_command(const struct load_command *cmd);

/**
 * Функция для вывода команды минимальной версии.
 *
 * @param cmd Указатель на команду минимальной версии.
 */
static void print_version_min_command(const struct load_command *cmd);

/**
 * Функция для вывода команды версии источника.
 *
 * @param cmd Указатель на команду версии источника.
 */
static void print_source_version_command(const struct load_command *cmd);

/**
 * Функция для вывода команды точки входа.
 *
 * @param cmd Указатель на команду точки входа.
 */
static void print_entry_point_command(const struct load_command *cmd);

/**
 * Функция для вывода команды начала функций.
 *
 * @param cmd Указатель на команду начала функций.
 * @param file Указатель на файл для вывода информации.
 */
static void print_function_starts_command(const struct load_command *cmd, FILE *file);

/**
 * Функция для вывода команды данных в коде.
 *
 * @param cmd Указатель на команду данных в коде.
 */
static void print_data_in_code_command(const struct load_command *cmd);

/**
 * Функция для вывода команды сигнатуры кода.
 *
 * @param cmd Указатель на команду сигнатуры кода.
 */
static void print_code_signature_command(const struct load_command *cmd);

/**
 * Функция для вывода команды информации о шифровании.
 *
 * @param cmd Указатель на команду информации о шифровании.
 */
static void print_encryption_info_command(const struct load_command *cmd);

/**
 * Функция для вывода команды пути загрузки.
 *
 * @param cmd Указатель на команду пути загрузки.
 */
static void print_rpath_command(const struct load_command *cmd);

/**
 * Функция для вывода команды версии сборки.
 *
 * @param cmd Указатель на команду версии сборки.
 */
static void print_build_version_command(const struct load_command *cmd);

/**
 * Функция для вывода команды опций линковщика.
 *
 * @param cmd Указатель на команду опций линковщика.
 */
static void print_linker_option_command(const struct load_command *cmd);

/**
 * Функция для вывода команды заметок.
 *
 * @param cmd Указатель на команду заметок.
 */
static void print_note_command(const struct load_command *cmd);


void print_mach_o_info(const MachOFile *mach_o_file, FILE *file) {
    if (!mach_o_file) {
        return;
    }

    print_header_info(mach_o_file);
    printf("===========================>SECURITY CHECK>========================================:\n");
    check_security_features(mach_o_file, file);
    printf("===========================<SECURITY CHECK<========================================:\n");
    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->command_count;

    for (uint32_t i = 0; i < ncmds; i++) {
        printf("Load Command %d:\n", i + 1);
        printf("  Command Type: %d\n", cmd->cmd);
        printf("  Command Size: %d\n", cmd->cmdsize);

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
                printf("  Unknown or Unhandled Command\n");
                break;
        }

        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
        printf("\n");
    }
}

void print_header_info(const MachOFile *mach_o_file) {
    printf("Mach-O Header:\n");
    if (mach_o_file->is_64_bit) {
        printf("  64-bit Mach-O File\n");
        printf("  Magic: 0x%x\n", mach_o_file->header.header64.magic);
        printf("  CPU Type: %d\n", mach_o_file->header.header64.cputype);
        printf("  CPU Subtype: %d\n", mach_o_file->header.header64.cpusubtype & ~CPU_SUBTYPE_MASK);
        printf("  File Type: %d\n", mach_o_file->header.header64.filetype);
        printf("  Number of Commands: %d\n", mach_o_file->header.header64.ncmds);
        printf("  Size of Commands: %d\n", mach_o_file->header.header64.sizeofcmds);
        printf("  Flags: 0x%x\n\n", mach_o_file->header.header64.flags);
    } else {
        printf("  32-bit Mach-O File\n");
        printf("  Magic: 0x%x\n", mach_o_file->header.header32.magic);
        printf("  CPU Type: %d\n", mach_o_file->header.header32.cputype);
        printf("  CPU Subtype: %d\n", mach_o_file->header.header32.cpusubtype & ~CPU_SUBTYPE_MASK);
        printf("  File Type: %d\n", mach_o_file->header.header32.filetype);
        printf("  Number of Commands: %d\n", mach_o_file->header.header32.ncmds);
        printf("  Size of Commands: %d\n", mach_o_file->header.header32.sizeofcmds);
        printf("  Flags: 0x%x\n\n", mach_o_file->header.header32.flags);
    }
}

static void print_segment_command(const struct load_command *cmd, bool is_64_bit) {
    if (is_64_bit) {
        struct segment_command_64 *seg_cmd = (struct segment_command_64 *) cmd;
        printf("  LC_SEGMENT_64\n");
        printf("  Segment Name: %.16s\n", seg_cmd->segname);
        printf("  VM Address: 0x%llx\n", seg_cmd->vmaddr);
        printf("  VM Size: 0x%llx\n", seg_cmd->vmsize);
        printf("  File Offset: 0x%llx\n", seg_cmd->fileoff);
        printf("  File Size: 0x%llx\n", seg_cmd->filesize);
        printf("  Max Prot: 0x%x\n", seg_cmd->maxprot);
        printf("  Init Prot: 0x%x\n", seg_cmd->initprot);
        printf("  Number of Sections: %d\n", seg_cmd->nsects);
        printf("  Flags: 0x%x\n", seg_cmd->flags);
    } else {
        struct segment_command *seg_cmd = (struct segment_command *) cmd;
        printf("  LC_SEGMENT\n");
        printf("  Segment Name: %.16s\n", seg_cmd->segname);
        printf("  VM Address: 0x%x\n", seg_cmd->vmaddr);
        printf("  VM Size: 0x%x\n", seg_cmd->vmsize);
        printf("  File Offset: 0x%x\n", seg_cmd->fileoff);
        printf("  File Size: 0x%x\n", seg_cmd->filesize);
        printf("  Max Prot: 0x%x\n", seg_cmd->maxprot);
        printf("  Init Prot: 0x%x\n", seg_cmd->initprot);
        printf("  Number of Sections: %d\n", seg_cmd->nsects);
        printf("  Flags: 0x%x\n", seg_cmd->flags);
    }
}

static void print_symtab_command(const struct load_command *cmd, const MachOFile *mach_o_file, FILE *file) {
    struct symtab_command *symtab_cmd = (struct symtab_command *) cmd;
    printf("  LC_SYMTAB\n");
    printf("  Symbol Table Offset: %u\n", symtab_cmd->symoff);
    printf("  Number of Symbols: %u\n", symtab_cmd->nsyms);
    printf("  String Table Offset: %u\n", symtab_cmd->stroff);
    printf("  String Table Size: %u\n", symtab_cmd->strsize);

    if (symtab_cmd->nsyms > 0) {
        long current_offset = ftell(file);
        size_t symbol_size = mach_o_file->is_64_bit ? sizeof(struct nlist_64) : sizeof(struct nlist);
        size_t symbols_size = symtab_cmd->nsyms * symbol_size;

        void *symbols = malloc(symbols_size);
        if (!symbols) {
            fprintf(stderr, "Failed to allocate memory for symbol table.\n");
            fseek(file, current_offset, SEEK_SET);
            return;
        }

        fseek(file, symtab_cmd->symoff, SEEK_SET);
        if (fread(symbols, symbol_size, symtab_cmd->nsyms, file) != symtab_cmd->nsyms) {
            fprintf(stderr, "Failed to read symbol table.\n");
            free(symbols);
            fseek(file, current_offset, SEEK_SET);
            return;
        }

        char *string_table = malloc(symtab_cmd->strsize);
        if (!string_table) {
            fprintf(stderr, "Failed to allocate memory for string table.\n");
            free(symbols);
            fseek(file, current_offset, SEEK_SET);
            return;
        }

        fseek(file, symtab_cmd->stroff, SEEK_SET);
        if (fread(string_table, 1, symtab_cmd->strsize, file) != symtab_cmd->strsize) {
            fprintf(stderr, "Failed to read string table.\n");
            free(symbols);
            free(string_table);
            fseek(file, current_offset, SEEK_SET);
            return;
        }

        printf("  Symbols (first 10):\n");
        uint32_t num_symbols_to_print = symtab_cmd->nsyms > 10 ? 10 : symtab_cmd->nsyms;
        for (uint32_t j = 0; j < num_symbols_to_print; j++) {
            if (mach_o_file->is_64_bit) {
                struct nlist_64 *sym = &((struct nlist_64 *) symbols)[j];
                uint32_t strx = sym->n_un.n_strx;
                char *sym_name = (strx < symtab_cmd->strsize) ? (string_table + strx) : "<invalid>";
                printf("    [%u] %s\n", j, sym_name);
                printf("        n_value: 0x%llx\n", sym->n_value);
                printf("        n_type:  0x%x\n", sym->n_type);
                printf("        n_sect:  %u\n", sym->n_sect);
                printf("        n_desc:  0x%x\n", sym->n_desc);
            } else {
                struct nlist *sym = &((struct nlist *) symbols)[j];
                uint32_t strx = sym->n_un.n_strx;
                char *sym_name = (strx < symtab_cmd->strsize) ? (string_table + strx) : "<invalid>";
                printf("    [%u] %s\n", j, sym_name);
                printf("        n_value: 0x%x\n", sym->n_value);
                printf("        n_type:  0x%x\n", sym->n_type);
                printf("        n_sect:  %u\n", sym->n_sect);
                printf("        n_desc:  0x%x\n", sym->n_desc);
            }
        }

        free(symbols);
        free(string_table);
        fseek(file, current_offset, SEEK_SET);
    }
}

static void print_dysymtab_command(const struct load_command *cmd, FILE *file) {
    struct dysymtab_command *dysymtab_cmd = (struct dysymtab_command *) cmd;
    printf("  LC_DYSYMTAB\n");
    printf("  Indirect Symbol Table Offset: %u\n", dysymtab_cmd->indirectsymoff);
    printf("  Number of Indirect Symbols: %u\n", dysymtab_cmd->nindirectsyms);

    if (dysymtab_cmd->nindirectsyms > 0) {
        long current_offset = ftell(file);
        fseek(file, dysymtab_cmd->indirectsymoff, SEEK_SET);
        uint32_t *indirect_symbols = malloc(dysymtab_cmd->nindirectsyms * sizeof(uint32_t));
        if (indirect_symbols) {
            if (fread(indirect_symbols, sizeof(uint32_t), dysymtab_cmd->nindirectsyms, file) == dysymtab_cmd->nindirectsyms) {
                printf("  Indirect Symbols (first 10):\n");
                for (uint32_t j = 0; j < dysymtab_cmd->nindirectsyms && j < 10; j++) {
                    printf("    [%u]: %u\n", j, indirect_symbols[j]);
                }
            } else {
                fprintf(stderr, "Failed to read indirect symbols.\n");
            }
            free(indirect_symbols);
        } else {
            fprintf(stderr, "Failed to allocate memory for indirect symbols.\n");
        }
        fseek(file, current_offset, SEEK_SET);
    }
}

static void print_dylib_command(const struct load_command *cmd) {
    struct dylib_command *dylib_cmd = (struct dylib_command *) cmd;
    char *dylib_name = (char *) cmd + dylib_cmd->dylib.name.offset;

    uint32_t current_version = dylib_cmd->dylib.current_version;
    uint32_t compatibility_version = dylib_cmd->dylib.compatibility_version;

    // Извлекаем мажорную, минорную и патч-версии
    uint16_t current_major = (current_version >> 16) & 0xFFFF;
    uint8_t current_minor = (current_version >> 8) & 0xFF;
    uint8_t current_patch = current_version & 0xFF;

    uint16_t compat_major = (compatibility_version >> 16) & 0xFFFF;
    uint8_t compat_minor = (compatibility_version >> 8) & 0xFF;
    uint8_t compat_patch = compatibility_version & 0xFF;

    printf("  LC_LOAD_DYLIB\n");
    printf("  Dylib Name: %s\n", dylib_name);
    printf("  Time Stamp: %u\n", dylib_cmd->dylib.timestamp);
    printf("  Current Version: %u.%u.%u\n", current_major, current_minor, current_patch);
    printf("  Compatibility Version: %u.%u.%u\n", compat_major, compat_minor, compat_patch);
}

void print_dynamic_libraries(const MachOFile *mach_o_file) {
    if (!mach_o_file || !mach_o_file->commands) {
        fprintf(stderr, "Invalid Mach-O file or no load commands available.\n");
        return;
    }

    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->command_count;

    printf("Dynamic Libraries:\n");
    for (uint32_t i = 0; i < ncmds; i++) {
        switch (cmd->cmd) {
            case LC_LOAD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_REEXPORT_DYLIB:
            case LC_LOAD_UPWARD_DYLIB:
            case LC_LAZY_LOAD_DYLIB: {
                struct dylib_command *dylib_cmd = (struct dylib_command *) cmd;
                char *dylib_name = (char *) cmd + dylib_cmd->dylib.name.offset;

                uint32_t current_version = dylib_cmd->dylib.current_version;
                uint32_t compatibility_version = dylib_cmd->dylib.compatibility_version;

                // Извлекаем мажорную, минорную и патч-версии
                uint16_t current_major = (current_version >> 16) & 0xFFFF;
                uint8_t current_minor = (current_version >> 8) & 0xFF;
                uint8_t current_patch = current_version & 0xFF;

                uint16_t compat_major = (compatibility_version >> 16) & 0xFFFF;
                uint8_t compat_minor = (compatibility_version >> 8) & 0xFF;
                uint8_t compat_patch = compatibility_version & 0xFF;

                printf("  %s (Current Version: %u.%u.%u, Compatibility Version: %u.%u.%u)\n",
                       dylib_name,
                       current_major, current_minor, current_patch,
                       compat_major, compat_minor, compat_patch);
                break;
            }
            default:
                // Игнорируем остальные команды
                break;
        }
        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
    }
}

static void print_dylinker_command(const struct load_command *cmd) {
    struct dylinker_command *dylinker_cmd = (struct dylinker_command *) cmd;
    char *dyld_name = (char *) cmd + dylinker_cmd->name.offset;
    printf("  LC_LOAD_DYLINKER\n");
    printf("  Dyld Name: %s\n", dyld_name);
}

static void print_uuid_command(const struct load_command *cmd) {
    struct uuid_command *uuid_cmd = (struct uuid_command *) cmd;
    printf("  LC_UUID\n  UUID: ");
    for (int k = 0; k < 16; k++) {
        printf("%02x", uuid_cmd->uuid[k]);
        if (k == 3 || k == 5 || k == 7 || k == 9) printf("-");
    }
    printf("\n");
}

static void print_version_min_command(const struct load_command *cmd) {
    struct version_min_command *ver_min_cmd = (struct version_min_command *) cmd;
    printf("  LC_VERSION_MIN\n");
    printf("  Version: %u.%u\n", ver_min_cmd->version >> 16, ver_min_cmd->version & 0xffff);
    printf("  SDK: %u.%u\n", ver_min_cmd->sdk >> 16, ver_min_cmd->sdk & 0xffff);
}

static void print_source_version_command(const struct load_command *cmd) {
    struct source_version_command *src_version_cmd = (struct source_version_command *) cmd;
    uint64_t version = src_version_cmd->version;
    printf("  LC_SOURCE_VERSION\n");
    printf("  Version: %llu.%llu.%llu.%llu.%llu\n",
           (version >> 40) & 0xfffff,
           (version >> 30) & 0x3ff,
           (version >> 20) & 0x3ff,
           (version >> 10) & 0x3ff,
           version & 0x3ff);
}

static void print_entry_point_command(const struct load_command *cmd) {
    struct entry_point_command *entry_cmd = (struct entry_point_command *) cmd;
    printf("  LC_MAIN\n");
    printf("  Entry Offset: 0x%llx\n", entry_cmd->entryoff);
    printf("  Stack Size: 0x%llx\n", entry_cmd->stacksize);
}

static void print_function_starts_command(const struct load_command *cmd, FILE *file) {
    struct linkedit_data_command *func_starts_cmd = (struct linkedit_data_command *) cmd;
    printf("  LC_FUNCTION_STARTS\n");
    printf("  Data Offset: %u\n", func_starts_cmd->dataoff);
    printf("  Data Size: %u\n", func_starts_cmd->datasize);

    if (func_starts_cmd->datasize > 0) {
        long current_offset = ftell(file);
        fseek(file, func_starts_cmd->dataoff, SEEK_SET);
        uint8_t *data = malloc(func_starts_cmd->datasize);
        if (!data) {
            fprintf(stderr, "Failed to allocate memory for function starts data.\n");
            fseek(file, current_offset, SEEK_SET);
            return;
        }

        if (fread(data, 1, func_starts_cmd->datasize, file) != func_starts_cmd->datasize) {
            fprintf(stderr, "Failed to read function starts data.\n");
            free(data);
            fseek(file, current_offset, SEEK_SET);
            return;
        }

        const uint8_t *p = data;
        const uint8_t *end = data + func_starts_cmd->datasize;
        uint64_t address = 0;
        uint64_t function_start;

        printf("  Function Starts:\n");
        int count = 0;
        while (p < end) {
            uint64_t delta = decode_uleb128(&p, end);
            if (delta == 0) break;
            address += delta;
            function_start = address;
            printf("    [%-3d] 0x%llx\n", count, function_start);
            count++;
        }

        free(data);
        fseek(file, current_offset, SEEK_SET);
    }
}

static void print_data_in_code_command(const struct load_command *cmd) {
    struct linkedit_data_command *data_in_code_cmd = (struct linkedit_data_command *) cmd;
    printf("  LC_DATA_IN_CODE\n");
    printf("  Data Offset: %u\n", data_in_code_cmd->dataoff);
    printf("  Data Size: %u\n", data_in_code_cmd->datasize);
}

static void print_code_signature_command(const struct load_command *cmd) {
    struct linkedit_data_command *code_sig_cmd = (struct linkedit_data_command *) cmd;
    printf("  LC_CODE_SIGNATURE\n");
    printf("  Data Offset: %u\n", code_sig_cmd->dataoff);
    printf("  Data Size: %u\n", code_sig_cmd->datasize);
}

static void print_encryption_info_command(const struct load_command *cmd) {
    struct encryption_info_command *enc_info_cmd = (struct encryption_info_command *) cmd;
    printf("  LC_ENCRYPTION_INFO\n");
    printf("  Crypt Offset: %u\n", enc_info_cmd->cryptoff);
    printf("  Crypt Size: %u\n", enc_info_cmd->cryptsize);
    printf("  Crypt ID: %u\n", enc_info_cmd->cryptid);
}

static void print_rpath_command(const struct load_command *cmd) {
    struct rpath_command *rpath_cmd = (struct rpath_command *) cmd;
    char *path = (char *) cmd + rpath_cmd->path.offset;
    printf("  LC_RPATH\n  RPath: %s\n", path);
}

static void print_build_version_command(const struct load_command *cmd) {
    struct build_version_command *build_ver_cmd = (struct build_version_command *) cmd;
    printf("  LC_BUILD_VERSION\n");
    printf("  Platform: %u\n", build_ver_cmd->platform);
    printf("  Min OS Version: %u.%u.%u\n",
           (build_ver_cmd->minos >> 16) & 0xffff,
           (build_ver_cmd->minos >> 8) & 0xff,
           build_ver_cmd->minos & 0xff);
    printf("  SDK Version: %u.%u.%u\n",
           (build_ver_cmd->sdk >> 16) & 0xffff,
           (build_ver_cmd->sdk >> 8) & 0xff,
           build_ver_cmd->sdk & 0xff);
}

static void print_linker_option_command(const struct load_command *cmd) {
    struct linker_option_command *linker_opt_cmd = (struct linker_option_command *) cmd;
    uint32_t count = linker_opt_cmd->count;
    char *data = (char *) (linker_opt_cmd + 1);
    printf("  LC_LINKER_OPTION\n  Linker Options (%u):\n", count);
    for (uint32_t j = 0; j < count; j++) {
        printf("    %s\n", data);
        data += strlen(data) + 1;
    }
}

static void print_note_command(const struct load_command *cmd) {
    struct note_command *note_cmd = (struct note_command *) cmd;
    printf("  LC_NOTE\n");
    printf("  Data Owner: %s\n", note_cmd->data_owner);
    printf("  Offset: %llu\n", note_cmd->offset);
    printf("  Size: %llu\n", note_cmd->size);
}

static uint64_t decode_uleb128(const uint8_t **p, const uint8_t *end) {
    uint64_t result = 0;
    int shift = 0;
    while (*p < end) {
        uint8_t byte = **p;
        (*p)++;
        result |= (uint64_t) (byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) break;
        shift += 7;
    }
    return result;
}


