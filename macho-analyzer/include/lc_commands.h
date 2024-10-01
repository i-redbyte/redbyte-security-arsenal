#ifndef LC_COMMANDS_H
#define LC_COMMANDS_H

#include <stdio.h>
#include <string.h>
#include <ctype.h>

/**
 * Структура для хранения информации о команде LC.
 */
typedef struct {
    const char *name;
    const char *description_en;
    const char *description_ru;
} LCCommandInfo;

/**
 * Получает информацию о команде по ее имени.
 *
 * @param name Имя команды (например, "LC_REEXPORT_DYLIB").
 * @return Указатель на структуру LCCommandInfo или NULL, если команда не найдена.
 */
const LCCommandInfo* get_lc_command_info(const char *name);

/**
 * Выводит информацию о команде на указанном языке.
 *
 * @param info Указатель на структуру LCCommandInfo.
 * @param lang Язык ("en" для английского, "ru" для русского).
 */
void print_lc_command_info(const LCCommandInfo *info, const char *lang);

/**
 * Выводит информацию обо всех командах на указанном языке.
 *
 * @param lang Язык ("en" для английского, "ru" для русского).
 */
void print_all_lc_commands(const char *lang);

#endif // LC_COMMANDS_H
