#ifndef SECURITY_ANALYZER_H
#define SECURITY_ANALYZER_H

#include "macho_analyzer.h"

typedef struct {
    const char *function_name;
    const char *category;  // Категория проблемы, например, "string operation", "memory operation"
    const char *severity;  // Уровень критичности: "high", "medium", "low"
} UnsafeFunctionInfo;

// Список известных небезопасных функций
extern const UnsafeFunctionInfo unsafe_functions[];

/**
 * Анализирует символы в Mach-O файле на использование небезопасных функций.
 *
 * Функция проверяет таблицу символов в Mach-O файле на наличие известных небезопасных функций,
 * которые могут представлять угрозу безопасности (например, strcpy, sprintf и другие).
 *
 * @param mach_o_file Указатель на структуру MachOFile, содержащую информацию о командах загрузки.
 * @param file Указатель на открытый файл Mach-O для чтения таблицы символов.
 * @return 0 при успехе, -1 в случае ошибки.
 */
int analyze_unsafe_functions(const MachOFile *mach_o_file, FILE *file);

/**
 * Анализирует секции в Mach-O файле на наличие прав на запись и исполнение одновременно.
 *
 * Функция проверяет секции Mach-O файла и выявляет те, которые имеют одновременно права на запись и исполнение,
 * что является потенциально небезопасной конфигурацией и может привести к уязвимостям.
 *
 * @param mach_o_file Указатель на структуру MachOFile, содержащую информацию о командах загрузки и секциях.
 * @param file Указатель на открытый файл Mach-O для чтения данных секций.
 * @return 0 при успехе, -1 в случае ошибки.
 */
int analyze_section_permissions(const MachOFile *mach_o_file, FILE *file);

/**
 * Анализирует секции Mach-O файла на наличие отладочных символов.
 *
 * Функция проверяет секции Mach-O файла на наличие отладочных символов (например, секции __debug_info, __debug_line),
 * которые могут содержать информацию, используемую для отладки и потенциально раскрывающую внутреннюю структуру программы.
 *
 * @param mach_o_file Указатель на структуру MachOFile, содержащую информацию о командах загрузки и секциях.
 * @param file Указатель на открытый файл Mach-O для чтения данных секций.
 * @return 0 при успехе, -1 в случае ошибки.
 */
int analyze_debug_symbols(const MachOFile *mach_o_file, FILE *file);


#endif
