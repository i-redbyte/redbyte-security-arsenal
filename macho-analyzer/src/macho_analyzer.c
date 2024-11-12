#include "macho_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCrypto.h>

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
int analyze_code_signature(const MachOFile *mach_o_file, FILE *file) {
    if (!mach_o_file || !mach_o_file->commands || !file) {
        fprintf(stderr, "Invalid Mach-O file or no commands to process.\n");
        return -1;
    }

    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->command_count;
    struct linkedit_data_command *code_sig_cmd = NULL;

    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_CODE_SIGNATURE) {
            code_sig_cmd = (struct linkedit_data_command *)cmd;
            break;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    if (!code_sig_cmd) {
        printf("No Code Signature detected in this Mach-O file.\n");
        return 0;
    }

    printf("Code Signature detected. Verifying signature...\n");

    if (fseek(file, code_sig_cmd->dataoff, SEEK_SET) != 0) {
        perror("Failed to seek to code signature data");
        return -1;
    }

    uint8_t *signature_data = malloc(code_sig_cmd->datasize);
    if (!signature_data) {
        fprintf(stderr, "Failed to allocate memory for code signature data.\n");
        return -1;
    }

    if (fread(signature_data, 1, code_sig_cmd->datasize, file) != code_sig_cmd->datasize) {
        fprintf(stderr, "Failed to read code signature data.\n");
        free(signature_data);
        return -1;
    }

    uint32_t magic = *(uint32_t *)signature_data;
    if (magic != CSMAGIC_CODEDIRECTORY) {
        printf("Warning: Code Signature magic number does not match expected value.\n");
        free(signature_data);
        return -1;
    }

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

    if (cd->length != code_sig_cmd->datasize) {
        printf("Warning: Code Directory length does not match expected value.\n");
        free(signature_data);
        return -1;
    }

    printf("Code Directory version: 0x%x\n", cd->version);
    if (cd->version < 0x20100) {
        printf("Warning: Code Directory version is outdated. Consider updating for better security.\n");
    }

    if (cd->identOffset < code_sig_cmd->datasize) {
        char *identifier = (char *)(signature_data + cd->identOffset);
        printf("Code Directory identifier: %s\n", identifier);
    } else {
        printf("Warning: Invalid identifier offset in Code Directory.\n");
        free(signature_data);
        return -1;
    }

    uint8_t *hash_data = signature_data + cd->hashOffset;
    printf("Code Directory Hash (first 16 bytes): ");
    for (size_t i = 0; i < 16 && i < cd->length - cd->hashOffset; i++) {
        printf("%02x ", hash_data[i]);
    }
    printf("\n");

    uint8_t calculated_hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX sha_ctx;
    CC_SHA256_Init(&sha_ctx);
    CC_SHA256_Update(&sha_ctx, signature_data, cd->length);
    CC_SHA256_Final(calculated_hash, &sha_ctx);

    printf("Calculated SHA-256 Hash: ");
    for (size_t i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", calculated_hash[i]);
    }
    printf("\n");

    printf("Code Signature appears valid (based on preliminary checks).\n");

    free(signature_data);
    return 0;
}


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
        if (analyze_code_signature(mach_o_file, file) != 0) {
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

static int read_and_validate(FILE *file, void *buffer, size_t size, const char *err_msg) {
    if (fread(buffer, 1, size, file) != size) {
        fprintf(stderr, "%s\n", err_msg);
        return -1;
    }
    return 0;
}

void free_mach_o_file(MachOFile *mach_o_file) {
    if (mach_o_file && mach_o_file->commands) {
        free(mach_o_file->commands);
        mach_o_file->commands = NULL;
    }
}
