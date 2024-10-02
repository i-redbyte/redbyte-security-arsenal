#ifndef UI_H
#define UI_H

#include "../macho-analyzer/include/macho_analyzer.h"
#include <stdio.h>
#include <language_detector.h>

void ui_init();
void ui_end();

void ui_display_mach_o_info(MachOFile *mach_o_file, FILE *file);
void ui_display_dynamic_libraries(MachOFile *mach_o_file);
void ui_display_language_info(LanguageInfo *lang_info);
void ui_display_error(const char *message);
const char* ui_select_file();

#endif // UI_H
