#ifndef SECURITY_ANALYZER_H
#define SECURITY_ANALYZER_H

#include "macho_analyzer.h"
#include "hash_table.h"

/**
 * Структура, содержащая информацию о небезопасной функции.
 * @param function_name Имя небезопасной функции (например, strcpy, sprintf и т.д.).
 * @param category Категория проблемы (например, "string operation", "memory operation").
 * @param severity Уровень критичности: "high", "medium", "low".
 */
typedef struct {
    const char *function_name;
    const char *category;
    const char *severity;
} UnsafeFunctionInfo;

// Список известных небезопасных функций
extern const UnsafeFunctionInfo unsafe_functions[];

/**
 * Инициализирует таблицу небезопасных функций.
 *
 * Функция создает и заполняет хеш-таблицу известными небезопасными функциями для использования в анализе.
 *
 * @return Указатель на созданную хеш-таблицу или NULL в случае ошибки.
 */
HashTable *initialize_unsafe_function_table();

/**
 * Анализирует символы в Mach-O файле на использование небезопасных функций.
 *
 * Функция проверяет таблицу символов в Mach-O файле на наличие известных небезопасных функций,
 * которые могут представлять угрозу безопасности (например, strcpy, sprintf и другие).
 *
 * @param mach_o_file Указатель на структуру MachOFile, содержащую информацию о командах загрузки.
 * @param file Указатель на открытый файл Mach-O для чтения таблицы символов.
 * @param unsafe_function_table Указатель на хеш-таблицу небезопасных функций.
 * @return 0 при успехе, -1 в случае ошибки.
 */
int analyze_unsafe_functions(const MachOFile *mach_o_file, FILE *file, HashTable *unsafe_function_table);

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

#endif // SECURITY_ANALYZER_H