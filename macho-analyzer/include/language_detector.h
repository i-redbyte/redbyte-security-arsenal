#ifndef LANGUAGE_DETECTOR_H
#define LANGUAGE_DETECTOR_H

#include "macho_analyzer.h"

typedef struct {
    char language[64];
    char compiler[64];
} LanguageInfo;

int detect_language_and_compiler(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info);

#endif // LANGUAGE_DETECTOR_H
