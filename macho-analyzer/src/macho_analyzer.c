#include "macho_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach-o/fat.h>
#include <mach-o/swap.h>

/**
 * Функция для анализа заголовков Mach-O файла.
 * Читает заголовок Mach-O файла и сохраняет информацию в структуру MachOFile.
 *
 * @param file Указатель на открытый файл Mach-O.
 * @param mach_o_file Структура для хранения данных о файле Mach-O.
 * @return 0 при успешном выполнении, -1 в случае ошибки.
 */
static int analyze_mach_header(FILE *file, MachOFile *mach_o_file);

/**
 * Функция для анализа команд загрузки Mach-O файла.
 * Читает команды загрузки Mach-O и сохраняет их в структуру MachOFile.
 *
 * @param file Указатель на открытый файл Mach-O.
 * @param mach_o_file Структура для хранения команд загрузки.
 * @return 0 при успешном выполнении, -1 в случае ошибки.
 */
static int analyze_load_commands(FILE *file, MachOFile *mach_o_file);

/**
 * Функция для анализа заголовков Fat Binary.
 * Обрабатывает Fat Binary, извлекает информацию о каждой архитектуре и анализирует соответствующие Mach-O файлы.
 *
 * @param file Указатель на открытый файл Fat Binary.
 * @return 0 при успешном выполнении, -1 в случае ошибки.
 */
static int analyze_fat_binary(FILE *file);

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
 * Функция для чтения данных и проверки ошибок.
 * Обёртка над fread, которая проверяет успешность чтения данных и выводит сообщение об ошибке в случае неудачи.
 *
 * @param file Указатель на открытый файл.
 * @param buffer Буфер для хранения прочитанных данных.
 * @param size Количество байт для чтения.
 * @param err_msg Сообщение об ошибке для вывода в случае неудачи.
 * @return 0 при успешном выполнении, -1 в случае ошибки.
 */
static int read_and_validate(FILE *file, void *buffer, size_t size, const char *err_msg);

int analyze_mach_o(FILE *file, MachOFile *mach_o_file) {
    if (!file || !mach_o_file) {
        fprintf(stderr, "Invalid file or MachOFile structure.\n");
        return -1;
    }

    memset(mach_o_file, 0, sizeof(MachOFile));
    uint32_t magic;
    if (read_and_validate(file, &magic, sizeof(uint32_t), "Failed to read magic number") != 0) {
        return -1;
    }
    fseek(file, 0, SEEK_SET); // Возвращаемся в начало файла

    // Проверяем на Fat Binary
    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        if (analyze_fat_binary(file) != 0) {
            return -1;
        }
    } else {
        if (analyze_mach_header(file, mach_o_file) != 0) {
            return -1;
        }
        if (analyze_load_commands(file, mach_o_file) != 0) {
            return -1;
        }
    }

    return 0;
}


static int analyze_fat_binary(FILE *file) {
    struct fat_header fatHeader;
    if (read_and_validate(file, &fatHeader, sizeof(struct fat_header), "Failed to read fat header") != 0) {
        return -1;
    }

    uint32_t nfat_arch = OSSwapBigToHostInt32(fatHeader.nfat_arch);
    struct fat_arch *fatArchs = calloc(nfat_arch, sizeof(struct fat_arch));
    if (!fatArchs) {
        fprintf(stderr, "Memory allocation failed for fat_arch.\n");
        return -1;
    }

    if (read_and_validate(file, fatArchs, sizeof(struct fat_arch) * nfat_arch, "Failed to read fat_arch structures") != 0) {
        free(fatArchs);
        return -1;
    }

    printf("Fat Binary with %u architectures:\n\n", nfat_arch);

    for (uint32_t i = 0; i < nfat_arch; i++) {
        uint32_t offset = OSSwapBigToHostInt32(fatArchs[i].offset);
        if (fseek(file, offset, SEEK_SET) != 0) {
            fprintf(stderr, "Failed to seek to architecture %u.\n", i + 1);
            continue;
        }

        MachOFile arch_mach_o_file;
        if (analyze_mach_header(file, &arch_mach_o_file) != 0) {
            fprintf(stderr, "Failed to analyze Mach-O header for architecture %u.\n", i + 1);
            continue;
        }

        if (analyze_load_commands(file, &arch_mach_o_file) != 0) {
            fprintf(stderr, "Failed to analyze load commands for architecture %u.\n", i + 1);
            free_mach_o_file(&arch_mach_o_file);
            continue;
        }

        free_mach_o_file(&arch_mach_o_file);
    }

    free(fatArchs);
    return 0;
}

static int analyze_mach_header(FILE *file, MachOFile *mach_o_file) {
    uint32_t magic;
    if (read_and_validate(file, &magic, sizeof(uint32_t), "Failed to read magic number") != 0) {
        return -1;
    }
    fseek(file, -(long) sizeof(uint32_t), SEEK_CUR); // Возвращаемся назад

    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        mach_o_file->is_64_bit = 1;
        struct mach_header_64 header;
        if (read_and_validate(file, &header, sizeof(struct mach_header_64), "Failed to read 64-bit Mach-O header") != 0) {
            return -1;
        }
        mach_o_file->header.header64 = header;
    } else if (magic == MH_MAGIC || magic == MH_CIGAM) {
        mach_o_file->is_64_bit = 0;
        struct mach_header header;
        if (read_and_validate(file, &header, sizeof(struct mach_header), "Failed to read 32-bit Mach-O header") != 0) {
            return -1;
        }
        mach_o_file->header.header32 = header;
    } else {
        fprintf(stderr, "Unsupported file format or invalid magic number: 0x%x\n", magic);
        return -1;
    }
    return 0;
}

static int analyze_load_commands(FILE *file, MachOFile *mach_o_file) {
    uint32_t ncmds, sizeofcmds;
    if (mach_o_file->is_64_bit) {
        ncmds = mach_o_file->header.header64.ncmds;
        sizeofcmds = mach_o_file->header.header64.sizeofcmds;
    } else {
        ncmds = mach_o_file->header.header32.ncmds;
        sizeofcmds = mach_o_file->header.header32.sizeofcmds;
    }

    mach_o_file->commands = malloc(sizeofcmds);
    if (!mach_o_file->commands) {
        fprintf(stderr, "Failed to allocate memory for load commands.\n");
        return -1;
    }

    if (read_and_validate(file, mach_o_file->commands, sizeofcmds, "Failed to read load commands") != 0) {
        free(mach_o_file->commands);
        return -1;
    }

    mach_o_file->command_count = ncmds;
    return 0;
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

static int read_and_validate(FILE *file, void *buffer, size_t size, const char *err_msg) {
    if (fread(buffer, 1, size, file) != size) {
        fprintf(stderr, "%s\n", err_msg);
        return -1;
    }
    return 0;
}

void print_mach_o_info(const MachOFile *mach_o_file, FILE *file) {
    if (!mach_o_file) {
        return;
    }

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

    // Обработка и вывод информации о командах загрузки
    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->command_count;

    for (uint32_t i = 0; i < ncmds; i++) {
        printf("Load Command %d:\n", i + 1);
        printf("  Command Type: %d\n", cmd->cmd);
        printf("  Command Size: %d\n", cmd->cmdsize);

        switch (cmd->cmd) {
            case LC_SEGMENT: {
                printf("  LC_SEGMENT\n");
                struct segment_command *seg_cmd = (struct segment_command *) cmd;
                printf("  Segment Name: %.16s\n", seg_cmd->segname);
                printf("  VM Address: 0x%x\n", seg_cmd->vmaddr);
                printf("  VM Size: 0x%x\n", seg_cmd->vmsize);
                printf("  File Offset: 0x%x\n", seg_cmd->fileoff);
                printf("  File Size: 0x%x\n", seg_cmd->filesize);
                printf("  Max Prot: 0x%x\n", seg_cmd->maxprot);
                printf("  Init Prot: 0x%x\n", seg_cmd->initprot);
                printf("  Number of Sections: %d\n", seg_cmd->nsects);
                printf("  Flags: 0x%x\n", seg_cmd->flags);
                break;
            }
            case LC_SEGMENT_64: {
                printf("  LC_SEGMENT_64\n");
                struct segment_command_64 *seg_cmd = (struct segment_command_64 *) cmd;
                printf("  Segment Name: %.16s\n", seg_cmd->segname);
                printf("  VM Address: 0x%llx\n", seg_cmd->vmaddr);
                printf("  VM Size: 0x%llx\n", seg_cmd->vmsize);
                printf("  File Offset: 0x%llx\n", seg_cmd->fileoff);
                printf("  File Size: 0x%llx\n", seg_cmd->filesize);
                printf("  Max Prot: 0x%x\n", seg_cmd->maxprot);
                printf("  Init Prot: 0x%x\n", seg_cmd->initprot);
                printf("  Number of Sections: %d\n", seg_cmd->nsects);
                printf("  Flags: 0x%x\n", seg_cmd->flags);
                break;
            }
            case LC_SYMTAB: {
                printf("  LC_SYMTAB\n");
                struct symtab_command *symtab_cmd = (struct symtab_command *) cmd;
                printf("  Symbol Table Offset: %u\n", symtab_cmd->symoff);
                printf("  Number of Symbols: %u\n", symtab_cmd->nsyms);
                printf("  String Table Offset: %u\n", symtab_cmd->stroff);
                printf("  String Table Size: %u\n", symtab_cmd->strsize);

                if (symtab_cmd->nsyms > 0) {
                    // Сохраняем текущую позицию в файле
                    long current_offset = ftell(file);

                    // Определяем размер структуры символа
                    size_t symbol_size = mach_o_file->is_64_bit ? sizeof(struct nlist_64) : sizeof(struct nlist);
                    size_t symbols_size = symtab_cmd->nsyms * symbol_size;

                    // Выделяем память для таблицы символов
                    void *symbols = malloc(symbols_size);
                    if (!symbols) {
                        fprintf(stderr, "Failed to allocate memory for symbol table.\n");
                        fseek(file, current_offset, SEEK_SET);
                        break;
                    }

                    // Читаем таблицу символов
                    fseek(file, symtab_cmd->symoff, SEEK_SET);
                    if (fread(symbols, symbol_size, symtab_cmd->nsyms, file) != symtab_cmd->nsyms) {
                        fprintf(stderr, "Failed to read symbol table.\n");
                        free(symbols);
                        fseek(file, current_offset, SEEK_SET);
                        break;
                    }

                    // Выделяем память для таблицы строк
                    char *string_table = malloc(symtab_cmd->strsize);
                    if (!string_table) {
                        fprintf(stderr, "Failed to allocate memory for string table.\n");
                        free(symbols);
                        fseek(file, current_offset, SEEK_SET);
                        break;
                    }

                    // Читаем таблицу строк
                    fseek(file, symtab_cmd->stroff, SEEK_SET);
                    if (fread(string_table, 1, symtab_cmd->strsize, file) != symtab_cmd->strsize) {
                        fprintf(stderr, "Failed to read string table.\n");
                        free(symbols);
                        free(string_table);
                        fseek(file, current_offset, SEEK_SET);
                        break;
                    }

                    // Выводим первые несколько символов
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

                    // Освобождаем память
                    free(symbols);
                    free(string_table);
                    // Возвращаемся к предыдущей позиции в файле
                    fseek(file, current_offset, SEEK_SET);
                }
                break;
            }

            case LC_DYSYMTAB: {
                printf("  LC_DYSYMTAB\n");
                struct dysymtab_command *dysymtab_cmd = (struct dysymtab_command *) cmd;
                printf("  Indirect Symbol Table Offset: %u\n", dysymtab_cmd->indirectsymoff);
                printf("  Number of Indirect Symbols: %u\n", dysymtab_cmd->nindirectsyms);

                // Дополнительная обработка: чтение и вывод непрямых символов
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
                break;
            }
            case LC_LOAD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_REEXPORT_DYLIB:
            case LC_LOAD_UPWARD_DYLIB: {
                printf("  LC_LOAD_DYLIB\n");
                struct dylib_command *dylib_cmd = (struct dylib_command *) cmd;
                char *dylib_name = (char *) cmd + dylib_cmd->dylib.name.offset;
                printf("  Dylib Name: %s\n", dylib_name);
                printf("  Time Stamp: %u\n", dylib_cmd->dylib.timestamp);
                printf("  Current Version: %u\n", dylib_cmd->dylib.current_version);
                printf("  Compatibility Version: %u\n", dylib_cmd->dylib.compatibility_version);
                break;
            }
            case LC_LOAD_DYLINKER: {
                printf("  LC_LOAD_DYLINKER\n");
                struct dylinker_command *dylinker_cmd = (struct dylinker_command *) cmd;
                char *dyld_name = (char *) cmd + dylinker_cmd->name.offset;
                printf("  Dyld Name: %s\n", dyld_name);
                break;
            }
            case LC_UUID: {
                printf("  LC_UUID\n");
                struct uuid_command *uuid_cmd = (struct uuid_command *) cmd;
                printf("  UUID: ");
                for (int k = 0; k < 16; k++) {
                    printf("%02x", uuid_cmd->uuid[k]);
                    if (k == 3 || k == 5 || k == 7 || k == 9)
                        printf("-");
                }
                printf("\n");
                break;
            }
            case LC_VERSION_MIN_MACOSX:
            case LC_VERSION_MIN_IPHONEOS: {
                printf("  LC_VERSION_MIN\n");
                struct version_min_command *ver_min_cmd = (struct version_min_command *) cmd;
                printf("  Version: %u.%u\n", ver_min_cmd->version >> 16, ver_min_cmd->version & 0xffff);
                printf("  SDK: %u.%u\n", ver_min_cmd->sdk >> 16, ver_min_cmd->sdk & 0xffff);
                break;
            }
            case LC_SOURCE_VERSION: {
                printf("  LC_SOURCE_VERSION\n");
                struct source_version_command *src_version_cmd = (struct source_version_command *) cmd;
                uint64_t version = src_version_cmd->version;
                printf("  Version: %llu.%llu.%llu.%llu.%llu\n",
                       (version >> 40) & 0xfffff,
                       (version >> 30) & 0x3ff,
                       (version >> 20) & 0x3ff,
                       (version >> 10) & 0x3ff,
                       version & 0x3ff);
                break;
            }
            case LC_MAIN: {
                printf("  LC_MAIN\n");
                struct entry_point_command *entry_cmd = (struct entry_point_command *) cmd;
                printf("  Entry Offset: 0x%llx\n", entry_cmd->entryoff);
                printf("  Stack Size: 0x%llx\n", entry_cmd->stacksize);
                break;
            }
            case LC_FUNCTION_STARTS: {
                printf("  LC_FUNCTION_STARTS\n");
                struct linkedit_data_command *func_starts_cmd = (struct linkedit_data_command *) cmd;
                printf("  Data Offset: %u\n", func_starts_cmd->dataoff);
                printf("  Data Size: %u\n", func_starts_cmd->datasize);

                // Дополнительная обработка: чтение и вывод адресов функций
                if (func_starts_cmd->datasize > 0) {
                    // Сохраняем текущую позицию в файле
                    long current_offset = ftell(file);

                    // Переходим к смещению данных функции
                    fseek(file, func_starts_cmd->dataoff, SEEK_SET);

                    // Читаем данные
                    uint8_t *data = malloc(func_starts_cmd->datasize);
                    if (!data) {
                        fprintf(stderr, "Failed to allocate memory for function starts data.\n");
                        fseek(file, current_offset, SEEK_SET);
                        break;
                    }

                    if (fread(data, 1, func_starts_cmd->datasize, file) != func_starts_cmd->datasize) {
                        fprintf(stderr, "Failed to read function starts data.\n");
                        free(data);
                        fseek(file, current_offset, SEEK_SET);
                        break;
                    }

                    // Декодирование ULEB128 и вывод адресов функций
                    const uint8_t *p = data;
                    const uint8_t *end = data + func_starts_cmd->datasize;
                    uint64_t address = 0;
                    uint64_t function_start;

                    printf("  Function Starts:\n");
                    int count = 0;
                    while (p < end) {
                        uint64_t delta = decode_uleb128(&p, end);
                        if (delta == 0) {
                            break; // Конец списка
                        }
                        address += delta;
                        function_start = address;
                        printf("    [%-3d] 0x%llx\n", count, function_start);
                        count++;
                    }

                    free(data);
                    // Возвращаемся к предыдущей позиции в файле
                    fseek(file, current_offset, SEEK_SET);
                }
                break;
            }
            case LC_DATA_IN_CODE: {
                printf("  LC_DATA_IN_CODE\n");
                struct linkedit_data_command *data_in_code_cmd = (struct linkedit_data_command *) cmd;
                printf("  Data Offset: %u\n", data_in_code_cmd->dataoff);
                printf("  Data Size: %u\n", data_in_code_cmd->datasize);
                break;
            }
            case LC_CODE_SIGNATURE: {
                printf("  LC_CODE_SIGNATURE\n");
                struct linkedit_data_command *code_sig_cmd = (struct linkedit_data_command *) cmd;
                printf("  Data Offset: %u\n", code_sig_cmd->dataoff);
                printf("  Data Size: %u\n", code_sig_cmd->datasize);
                break;
            }
            case LC_ENCRYPTION_INFO:
            case LC_ENCRYPTION_INFO_64: {
                printf("  LC_ENCRYPTION_INFO\n");
                struct encryption_info_command *enc_info_cmd = (struct encryption_info_command *) cmd;
                printf("  Crypt Offset: %u\n", enc_info_cmd->cryptoff);
                printf("  Crypt Size: %u\n", enc_info_cmd->cryptsize);
                printf("  Crypt ID: %u\n", enc_info_cmd->cryptid);
                break;
            }
            case LC_RPATH: {
                printf("  LC_RPATH\n");
                struct rpath_command *rpath_cmd = (struct rpath_command *) cmd;
                char *path = (char *) cmd + rpath_cmd->path.offset;
                printf("  RPath: %s\n", path);
                break;
            }
            case LC_BUILD_VERSION: {
                printf("  LC_BUILD_VERSION\n");
                struct build_version_command *build_ver_cmd = (struct build_version_command *) cmd;
                printf("  Platform: %u\n", build_ver_cmd->platform);
                printf("  Min OS Version: %u.%u.%u\n",
                       (build_ver_cmd->minos >> 16) & 0xffff,
                       (build_ver_cmd->minos >> 8) & 0xff,
                       build_ver_cmd->minos & 0xff);
                printf("  SDK Version: %u.%u.%u\n",
                       (build_ver_cmd->sdk >> 16) & 0xffff,
                       (build_ver_cmd->sdk >> 8) & 0xff,
                       build_ver_cmd->sdk & 0xff);
                break;
            }
            case LC_LINKER_OPTION: {
                printf("  LC_LINKER_OPTION\n");
                struct linker_option_command *linker_opt_cmd = (struct linker_option_command *) cmd;
                uint32_t count = linker_opt_cmd->count;
                char *data = (char *) (linker_opt_cmd + 1);
                printf("  Linker Options (%u):\n", count);
                for (uint32_t j = 0; j < count; j++) {
                    printf("    %s\n", data);
                    data += strlen(data) + 1;
                }
                break;
            }
            case LC_NOTE: {
                printf("  LC_NOTE\n");
                struct note_command *note_cmd = (struct note_command *) cmd;
                printf("  Data Owner: %s\n", note_cmd->data_owner);
                printf("  Offset: %llu\n", note_cmd->offset);
                printf("  Size: %llu\n", note_cmd->size);
                break;
            }
            default:
                printf("  Unknown or Unhandled Command\n");
                break;
        }

        // Переходим к следующей команде загрузки
        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
        printf("\n");
    }
}

void free_mach_o_file(MachOFile *mach_o_file) {
    if (mach_o_file && mach_o_file->commands) {
        free(mach_o_file->commands);
        mach_o_file->commands = NULL;
    }
}
