#ifndef MACHO_ANALYZER_MACHO_PRINTER_H
#define MACHO_ANALYZER_MACHO_PRINTER_H

#include "macho_analyzer.h"
#include <mach-o/nlist.h>

/**
 * Выводит информацию о Mach-O файле.
 *
 * @param mach_o_file Структура, содержащая данные о Mach-O.
 * @param file Указатель на исходный файл Mach-O.
 */
void print_mach_o_info(const MachOFile *mach_o_file, FILE *file);

/**
 * @brief Выводит список динамических библиотек, используемых Mach-O файлом.
 *
 * Эта функция проходит по командам загрузки в Mach-O файле и собирает информацию
 * обо всех динамических библиотеках (например, LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB).
 * Затем она выводит имена библиотек вместе с их текущими и совместимыми версиями.
 *
 * @param mach_o_file Указатель на структуру MachOFile, содержащую данные Mach-O.
 */
void print_dynamic_libraries(const MachOFile *mach_o_file);

/**
 * Функция для вывода информации заголовка Mach-O файла.
 *
 * @param mach_o_file Указатель на структуру MachOFile, содержащую информацию о файле.
 */
void print_header_info(const MachOFile *mach_o_file);

#endif //MACHO_ANALYZER_MACHO_PRINTER_H
