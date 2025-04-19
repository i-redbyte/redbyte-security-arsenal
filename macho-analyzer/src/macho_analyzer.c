#include "macho_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCrypto.h>
#include <macho_printer.h>
#include <CommonCrypto/CommonDigest.h>

#define CSMAGIC_CODEDIRECTORY 0xfade0c02
#define CSMAGIC_BLOBWRAPPER 0xfade0b01

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
int analyze_load_commands(FILE *file, MachOFile *mach_o_file);

/**
 * Функция для анализа заголовков Fat Binary.
 * Обрабатывает Fat Binary, извлекает информацию о каждой архитектуре и анализирует соответствующие Mach-O файлы.
 *
 * @param file Указатель на открытый файл Fat Binary.
 * @return 0 при успешном выполнении, -1 в случае ошибки.
 */
int analyze_fat_binary(FILE *file);

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

/**
 * Функция для более глубокого анализа секции LC_CODE_SIGNATURE в Mach-O файле.
 * Проверяет наличие LC_CODE_SIGNATURE и проверяет целостность подписи, а также её валидность.
 *
 * @param mach_o_file Структура MachOFile для хранения информации о файле.
 * @param file Указатель на открытый файл Mach-O для доступа к данным подписи.
 * @return 0 при успешной проверке, -1 в случае ошибки.
 */


/**
 * Анализирует подпись кода в Mach-O файле.
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 * @param file Указатель на файл для чтения данных подписи.
 * @return 0 при успехе, -1 в случае ошибки.
 */
int analyze_code_signature(const MachOFile *mach_o_file, FILE *file) {
    if (!mach_o_file || !mach_o_file->commands || !file) {
        fprintf(stderr, "Ошибка: Неверный Mach-O файл или отсутствуют команды для обработки.\n");
        return -1;
    }

    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->load_command_count; // Исправлено: load_command_count
    struct linkedit_data_command *code_sig_cmd = NULL;

    // Поиск команды подписи кода
    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_CODE_SIGNATURE) {
            code_sig_cmd = (struct linkedit_data_command *)cmd;
            break;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    if (!code_sig_cmd) {
        printf("Подпись кода не обнаружена в данном Mach-O файле.\n");
        return 0;
    }

    printf("Подпись кода обнаружена. Проверка подписи...\n");

    // Перемещение к данным подписи
    if (fseek(file, code_sig_cmd->dataoff, SEEK_SET) != 0) {
        perror("Ошибка: Не удалось переместиться к данным подписи кода");
        return -1;
    }

    // Выделение памяти для данных подписи
    uint8_t *signature_data = malloc(code_sig_cmd->datasize);
    if (!signature_data) {
        fprintf(stderr, "Ошибка: Не удалось выделить память для данных подписи кода.\n");
        return -1;
    }

    // Чтение данных подписи
    if (fread(signature_data, 1, code_sig_cmd->datasize, file) != code_sig_cmd->datasize) {
        fprintf(stderr, "Ошибка: Не удалось прочитать данные подписи кода.\n");
        free(signature_data);
        return -1;
    }

    // Проверка magic-числа подписи
    uint32_t magic = *(uint32_t *)signature_data;
    if (magic != CSMAGIC_CODEDIRECTORY) {
        printf("Предупреждение: Magic-число подписи кода не соответствует ожидаемому значению.\n");
        free(signature_data);
        return -1;
    }

    // Структура директории кода
    struct code_directory {
        uint32_t magic;
        uint32_t length;
        uint32_t version;
        uint32_t flags;
        uint32_t hashOffset;
        uint32_t identOffset;
        uint32_t nSpecialSlots;
        uint32_t nCodeSlots;
        uint32_t codeLimit;
        uint8_t hashSize;
        uint8_t hashType;
        uint8_t platform;
        uint8_t pageSize;
        uint32_t spare2;
        uint32_t scatterOffset;
    };

    struct code_directory *cd = (struct code_directory *)signature_data;

    // Проверка длины директории кода
    if (cd->length != code_sig_cmd->datasize) {
        printf("Предупреждение: Длина директории кода не соответствует ожидаемому значению.\n");
        free(signature_data);
        return -1;
    }

    printf("Версия директории кода: 0x%x\n", cd->version);
    if (cd->version < 0x20100) {
        printf("Предупреждение: Версия директории кода устарела. Рекомендуется обновление для повышения безопасности.\n");
    }

    // Вывод идентификатора
    if (cd->identOffset < code_sig_cmd->datasize) {
        char *identifier = (char *)(signature_data + cd->identOffset);
        printf("Идентификатор директории кода: %s\n", identifier);
    } else {
        printf("Предупреждение: Неверное смещение идентификатора в директории кода.\n");
        free(signature_data);
        return -1;
    }

    // Вывод первых 16 байт хеша
    uint8_t *hash_data = signature_data + cd->hashOffset;
    printf("Хеш директории кода (первые 16 байт): ");
    for (size_t i = 0; i < 16 && i < cd->length - cd->hashOffset; i++) {
        printf("%02x ", hash_data[i]);
    }
    printf("\n");

    // Вычисление SHA-256 хеша
    uint8_t calculated_hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX sha_ctx;
    CC_SHA256_Init(&sha_ctx);
    CC_SHA256_Update(&sha_ctx, signature_data, cd->length);
    CC_SHA256_Final(calculated_hash, &sha_ctx);

    printf("Вычисленный SHA-256 хеш: ");
    for (size_t i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", calculated_hash[i]);
    }
    printf("\n");

    printf("Подпись кода выглядит действительной (на основе предварительных проверок).\n");

    free(signature_data);
    return 0;
}

int analyze_mach_o(FILE *file, MachOFile *mach_o_file) {
    if (!file || !mach_o_file) {
        fprintf(stderr, "Ошибка: NULL указатель для файла или структуры MachOFile\n");
        return -1;
    }

    // Проверяем размер файла
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    if (file_size < sizeof(uint32_t)) {
        fprintf(stderr, "Ошибка: Файл слишком мал для Mach-O\n");
        return -1;
    }
    rewind(file);

    // Инициализируем структуру MachOFile
    memset(mach_o_file, 0, sizeof(MachOFile));

    // Читаем magic number
    uint32_t magic;
    if (fread(&magic, sizeof(uint32_t), 1, file) != 1) {
        fprintf(stderr, "Ошибка чтения magic number\n");
        return -1;
    }
    fseek(file, 0, SEEK_SET); // Возвращаемся к началу

    bool is_64_bit = false;
    bool is_big_endian = false;

    // Определяем формат файла
    switch (magic) {
        case MH_MAGIC_64:
            is_64_bit = true;
            is_big_endian = false;
            break;
        case MH_CIGAM_64:
            is_64_bit = true;
            is_big_endian = true;
            break;
        case MH_MAGIC:
            is_64_bit = false;
            is_big_endian = false;
            break;
        case MH_CIGAM:
            is_64_bit = false;
            is_big_endian = true;
            break;
        default:
            fprintf(stderr, "Неподдерживаемый magic: 0x%x\n", magic);
            return -1;
    }

    // Сохраняем magic и флаги
    mach_o_file->magic = magic;
    mach_o_file->is_64_bit = is_64_bit;

    // Отладочная информация
    printf("Magic: 0x%x, is_64_bit: %d, is_big_endian: %d\n", magic, is_64_bit, is_big_endian);

    if (is_64_bit) {
        struct mach_header_64 header;
        if (fread(&header, sizeof(header), 1, file) != 1) {
            fprintf(stderr, "Ошибка чтения заголовка Mach-O 64-bit\n");
            return -1;
        }

        // Проверяем валидность заголовка
        if (header.cputype == 0) {
            fprintf(stderr, "Ошибка: Недопустимый CPU Type в заголовке\n");
            return -1;
        }
        if (header.ncmds == 0) {
            fprintf(stderr, "Ошибка: Нет команд загрузки в заголовке\n");
            return -1;
        }

        // Заполняем структуру с учётом порядка байтов
        mach_o_file->cpu_type = is_big_endian ? OSSwapBigToHostInt32(header.cputype) : header.cputype;
        mach_o_file->cpu_subtype = is_big_endian ? OSSwapBigToHostInt32(header.cpusubtype) : header.cpusubtype;
        mach_o_file->file_type = is_big_endian ? OSSwapBigToHostInt32(header.filetype) : header.filetype;
        mach_o_file->flags = is_big_endian ? OSSwapBigToHostInt32(header.flags) : header.flags;
        mach_o_file->load_command_count = is_big_endian ? OSSwapBigToHostInt32(header.ncmds) : header.ncmds;
        mach_o_file->sizeofcmds = is_big_endian ? OSSwapBigToHostInt32(header.sizeofcmds) : header.sizeofcmds;
        mach_o_file->header_size = sizeof(struct mach_header_64);

        // Отладочная информация после заполнения структуры
        printf("64-bit header: cputype=0x%x, ncmds=%u, sizeofcmds=%u\n",
               mach_o_file->cpu_type, mach_o_file->load_command_count, mach_o_file->sizeofcmds);
        printf("MachOFile after filling: magic=0x%x, cputype=0x%x, ncmds=%u\n",
               mach_o_file->magic, mach_o_file->cpu_type, mach_o_file->load_command_count);
    } else {
        struct mach_header header;
        if (fread(&header, sizeof(header), 1, file) != 1) {
            fprintf(stderr, "Ошибка чтения заголовка Mach-O 32-bit\n");
            return -1;
        }

        // Проверяем валидность заголовка
        if (header.cputype == 0) {
            fprintf(stderr, "Ошибка: Недопустимый CPU Type в заголовке\n");
            return -1;
        }
        if (header.ncmds == 0) {
            fprintf(stderr, "Ошибка: Нет команд загрузки в заголовке\n");
            return -1;
        }

        // Заполняем структуру
        mach_o_file->cpu_type = is_big_endian ? OSSwapBigToHostInt32(header.cputype) : header.cputype;
        mach_o_file->cpu_subtype = is_big_endian ? OSSwapBigToHostInt32(header.cpusubtype) : header.cpusubtype;
        mach_o_file->file_type = is_big_endian ? OSSwapBigToHostInt32(header.filetype) : header.filetype;
        mach_o_file->flags = is_big_endian ? OSSwapBigToHostInt32(header.flags) : header.flags;
        mach_o_file->load_command_count = is_big_endian ? OSSwapBigToHostInt32(header.ncmds) : header.ncmds;
        mach_o_file->sizeofcmds = is_big_endian ? OSSwapBigToHostInt32(header.sizeofcmds) : header.sizeofcmds;
        mach_o_file->header_size = sizeof(struct mach_header);

        // Отладочная информация
        printf("32-bit header: cputype=0x%x, ncmds=%u, sizeofcmds=%u\n",
               mach_o_file->cpu_type, mach_o_file->load_command_count, mach_o_file->sizeofcmds);
        printf("MachOFile after filling: magic=0x%x, cputype=0x%x, ncmds=%u\n",
               mach_o_file->magic, mach_o_file->cpu_type, mach_o_file->load_command_count);
    }

    return 0;
}

const char *get_arch_name(cpu_type_t cpu, cpu_subtype_t sub) {
    bool is64 = (cpu & CPU_ARCH_ABI64) != 0;
    cpu_type_t baseCpu = cpu & ~CPU_ARCH_ABI64;
    switch (baseCpu) {
        case CPU_TYPE_X86:
            return is64 ? "x86_64" : "i386";
        case CPU_TYPE_ARM:
            return is64 ? "arm64" : "arm";
        case CPU_TYPE_POWERPC:
            return is64 ? "powerpc64" : "powerpc";
        default:
            return "unknown";
    }
}

int analyze_fat_binary(FILE *file) {
    struct fat_header fatHeader;

    if (fread(&fatHeader, sizeof(struct fat_header), 1, file) != 1) {
        fprintf(stderr, "Failed to read fat header\n");
        return -1;
    }

    uint32_t nfat_arch = OSSwapBigToHostInt32(fatHeader.nfat_arch);

    struct fat_arch *fatArchs = calloc(nfat_arch, sizeof(struct fat_arch));
    if (!fatArchs) {
        fprintf(stderr, "Memory allocation failed for fat_arch.\n");
        return -1;
    }

    for (uint32_t i = 0; i < nfat_arch; i++) {
        if (fread(&fatArchs[i], sizeof(struct fat_arch), 1, file) != 1) {
            fprintf(stderr, "Failed to read fat_arch %u\n", i);
            free(fatArchs);
            return -1;
        }
    }

    printf("Fat Binary with %u architectures:\n\n", nfat_arch);

    for (uint32_t i = 0; i < nfat_arch; i++) {
        cpu_type_t cpuType = OSSwapBigToHostInt32(fatArchs[i].cputype);
        cpu_subtype_t cpuSubtype = OSSwapBigToHostInt32(fatArchs[i].cpusubtype);
        uint32_t offset = OSSwapBigToHostInt32(fatArchs[i].offset);
        uint32_t size = OSSwapBigToHostInt32(fatArchs[i].size);

        printf("---- Начинаем анализ архитектуры %u (%s) ----\n", i + 1, get_arch_name(cpuType, cpuSubtype));
        printf("Offset = %u, Size = %u\n", offset, size);

        if (fseek(file, offset, SEEK_SET) != 0) {
            fprintf(stderr, "Failed to seek to architecture %u (offset %u).\n", i + 1, offset);
            continue;
        }

        MachOFile arch_mach_o_file;
        memset(&arch_mach_o_file, 0, sizeof(MachOFile)); // обнуляем, чтобы избежать мусора

        if (analyze_mach_header(file, &arch_mach_o_file) != 0) {
            fprintf(stderr, "Failed to analyze Mach-O header for architecture %u.\n", i + 1);
            continue;
        }

        if (analyze_load_commands(file, &arch_mach_o_file) != 0) {
            fprintf(stderr, "Failed to analyze load commands for architecture %u.\n", i + 1);
            free_mach_o_file(&arch_mach_o_file);
            continue;
        }

        if (analyze_code_signature(&arch_mach_o_file, file) != 0) {
            fprintf(stderr, "Code signature verification failed for architecture %u.\n", i + 1);
        }

        const char *archName = get_arch_name(cpuType, cpuSubtype);
        printf("Архитектура %u (%s):\n", i + 1, archName);

        print_mach_o_info(&arch_mach_o_file, file);
        printf("\n");

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

/**
 * Анализирует команды загрузки Mach-O файла и заполняет соответствующие поля структуры MachOFile.
 *
 * @param file Указатель на файл.
 * @param mach_o_file Структура с данными о Mach-O.
 * @return 0 при успехе, -1 в случае ошибки.
 */
int analyze_load_commands(FILE *file, MachOFile *mach_o_file) {
    if (!file || !mach_o_file) {
        fprintf(stderr, "Ошибка: NULL указатель на файл или MachOFile\n");
        return -1;
    }

    // Проверяем, что заголовок валиден
    if (mach_o_file->load_command_count == 0 || mach_o_file->sizeofcmds == 0) {
        fprintf(stderr, "Ошибка: Нет команд загрузки\n");
        return -1;
    }

    // Выделяем память для команд
    mach_o_file->commands = malloc(mach_o_file->sizeofcmds);
    if (!mach_o_file->commands) {
        fprintf(stderr, "Ошибка: Не удалось выделить память для команд загрузки\n");
        return -1;
    }

    // Читаем команды
    if (fread(mach_o_file->commands, mach_o_file->sizeofcmds, 1, file) != 1) {
        fprintf(stderr, "Ошибка: Не удалось прочитать команды загрузки\n");
        free(mach_o_file->commands);
        mach_o_file->commands = NULL;
        return -1;
    }

    // Подсчитываем сегменты и библиотеки
    struct load_command *cmd = mach_o_file->commands;
    uint32_t segment_count = 0;
    uint32_t dylib_count = 0;
    for (uint32_t i = 0; i < mach_o_file->load_command_count; i++) {
        if (cmd->cmd == LC_SEGMENT || cmd->cmd == LC_SEGMENT_64) {
            segment_count++;
        } else if (cmd->cmd == LC_LOAD_DYLIB || cmd->cmd == LC_LOAD_WEAK_DYLIB ||
                   cmd->cmd == LC_REEXPORT_DYLIB || cmd->cmd == LC_LOAD_UPWARD_DYLIB ||
                   cmd->cmd == LC_LAZY_LOAD_DYLIB) {
            dylib_count++;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    // Выделяем память для сегментов и библиотек
    mach_o_file->segments = calloc(segment_count, sizeof(Segment));
    mach_o_file->dylibs = calloc(dylib_count, sizeof(Dylib));
    if (!mach_o_file->segments || !mach_o_file->dylibs) {
        fprintf(stderr, "Ошибка: Не удалось выделить память для сегментов или библиотек\n");
        free(mach_o_file->commands);
        free(mach_o_file->segments);
        free(mach_o_file->dylibs);
        mach_o_file->commands = NULL;
        mach_o_file->segments = NULL;
        mach_o_file->dylibs = NULL;
        return -1;
    }
    mach_o_file->segment_count = segment_count;
    mach_o_file->dylib_count = dylib_count;

    // Заполняем сегменты и библиотеки
    cmd = mach_o_file->commands;
    uint32_t seg_index = 0;
    uint32_t dylib_index = 0;
    for (uint32_t i = 0; i < mach_o_file->load_command_count; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg_cmd = (struct segment_command_64 *)cmd;
            Segment *seg = &mach_o_file->segments[seg_index++];
            strncpy(seg->segname, seg_cmd->segname, 16);
            seg->segname[16] = '\0';
            seg->vmaddr = seg_cmd->vmaddr;
            seg->vmsize = seg_cmd->vmsize;
            seg->fileoff = seg_cmd->fileoff;
            seg->filesize = seg_cmd->filesize;
            seg->maxprot = seg_cmd->maxprot;
            seg->initprot = seg_cmd->initprot;
            seg->nsects = seg_cmd->nsects;
            seg->flags = seg_cmd->flags;
            // Заполнение секций (при необходимости)
        } else if (cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg_cmd = (struct segment_command *)cmd;
            Segment *seg = &mach_o_file->segments[seg_index++];
            strncpy(seg->segname, seg_cmd->segname, 16);
            seg->segname[16] = '\0';
            seg->vmaddr = seg_cmd->vmaddr;
            seg->vmsize = seg_cmd->vmsize;
            seg->fileoff = seg_cmd->fileoff;
            seg->filesize = seg_cmd->filesize;
            seg->maxprot = seg_cmd->maxprot;
            seg->initprot = seg_cmd->initprot;
            seg->nsects = seg_cmd->nsects;
            seg->flags = seg_cmd->flags;
            // Заполнение секций (при необходимости)
        } else if (cmd->cmd == LC_LOAD_DYLIB || cmd->cmd == LC_LOAD_WEAK_DYLIB ||
                   cmd->cmd == LC_REEXPORT_DYLIB || cmd->cmd == LC_LOAD_UPWARD_DYLIB ||
                   cmd->cmd == LC_LAZY_LOAD_DYLIB) {
            struct dylib_command *dylib_cmd = (struct dylib_command *)cmd;
            Dylib *dylib = &mach_o_file->dylibs[dylib_index++];
            char *name = (char *)cmd + dylib_cmd->dylib.name.offset;
            dylib->name = strdup(name);
            if (!dylib->name) {
                fprintf(stderr, "Ошибка: Не удалось выделить память для имени библиотеки\n");
                // Освобождаем уже выделенные ресурсы
                for (uint32_t j = 0; j < dylib_index; j++) {
                    free(mach_o_file->dylibs[j].name);
                }
                free(mach_o_file->dylibs);
                free(mach_o_file->segments);
                free(mach_o_file->commands);
                mach_o_file->dylibs = NULL;
                mach_o_file->segments = NULL;
                mach_o_file->commands = NULL;
                return -1;
            }
            dylib->timestamp = dylib_cmd->dylib.timestamp;
            dylib->current_version = dylib_cmd->dylib.current_version;
            dylib->compatibility_version = dylib_cmd->dylib.compatibility_version;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    return 0;
}

static int read_and_validate(FILE *file, void *buffer, size_t size, const char *err_msg) {
    if (fread(buffer, 1, size, file) != size) {
        fprintf(stderr, "%s\n", err_msg);
        return -1;
    }
    return 0;
}

void free_mach_o_file(MachOFile *mf) {
    if (!mf) {
        fprintf(stderr, "Ошибка: NULL указатель на MachOFile\n");
        return;
    }

    // Освобождаем команды загрузки
    if (mf->commands) {
        free(mf->commands);
        mf->commands = NULL;
    }

    // Освобождаем динамические библиотеки
    if (mf->dylibs) {
        for (uint32_t i = 0; i < mf->dylib_count; ++i) {
            if (mf->dylibs[i].name) {
                free(mf->dylibs[i].name);
                mf->dylibs[i].name = NULL;
            }
        }
        free(mf->dylibs);
        mf->dylibs = NULL;
    }

    // Освобождаем сегменты
    if (mf->segments) {
        for (uint32_t i = 0; i < mf->segment_count; ++i) {
            if (mf->segments[i].sections) {
                free(mf->segments[i].sections);
                mf->segments[i].sections = NULL;
            }
            if (mf->segments[i].sections32) {
                free(mf->segments[i].sections32);
                mf->segments[i].sections32 = NULL;
            }
        }
        free(mf->segments);
        mf->segments = NULL;
    }

    // Сбрасываем счётчики
    mf->dylib_count = 0;
    mf->segment_count = 0;
    mf->load_command_count = 0;
}