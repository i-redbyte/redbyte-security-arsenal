#ifndef MAC_SECURITY_MACHO_PRINTER_H
#define MAC_SECURITY_MACHO_PRINTER_H

#include "macho_analyzer.h"
#include <mach-o/nlist.h>

/**
 * Выводит информацию о Mach-O файле.
 *
 * @param mach_o_file Структура, содержащая данные о Mach-O.
 * @param file Указатель на исходный файл Mach-O.
 */
void print_mach_o_info(const MachOFile *mach_o_file, FILE *file);

#endif //MAC_SECURITY_MACHO_PRINTER_H
