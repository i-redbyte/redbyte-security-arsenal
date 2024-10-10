#ifndef MACHO_ANALYZER_SECURITY_CHECK_H
#define MACHO_ANALYZER_SECURITY_CHECK_H

#include "macho_analyzer.h"
#include <stdbool.h>

/**
 * Проверяет наличие защитных механизмов в Mach-O файле.
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 */
void check_security_features(const MachOFile *mach_o_file, FILE *file);

#endif //MACHO_ANALYZER_SECURITY_CHECK_H
