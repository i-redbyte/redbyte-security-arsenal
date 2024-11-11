#ifndef MACHO_ANALYZER_LC_COMMANDS_H
#define MACHO_ANALYZER_LC_COMMANDS_H

#include <stdio.h>
#include <string.h>
#include <ctype.h>

/**
 * Перечисление для поддерживаемых языков.
 */
typedef enum {
    LANG_EN, // Английский язык
    LANG_RU  // Русский язык
} Language;
/**
 * Структура для хранения информации о команде LC.
 */
typedef struct {
    const char *name;
    const char *description_en;
    const char *description_ru;
} LCCommandInfo;

/**
 * Получает информацию о команде по её имени.
 *
 * @param name Имя команды (например, "LC_REEXPORT_DYLIB").
 * @return Указатель на структуру LCCommandInfo или NULL, если команда не найдена.
 */
const LCCommandInfo *get_lc_command_info(const char *name);

/**
 * Выводит информацию о команде на указанном языке.
 *
 * @param info Указатель на структуру LCCommandInfo.
 * @param lang Язык вывода (LANG_EN для английского, LANG_RU для русского).
 */
void print_lc_command_info(const LCCommandInfo *info, Language lang);

/**
 * Выводит информацию обо всех командах на указанном языке.
 *
 * @param lang Язык вывода (LANG_EN для английского, LANG_RU для русского).
 */
void print_all_lc_commands(Language lang);

/**
 * Инициализация хеш-таблицы с командами LC.
 */
void initialize_lc_command_table();

/**
 * Освобождение памяти, выделенной для хеш-таблицы LC команд.
 */
void destroy_lc_command_table();

#endif // MACHO_ANALYZER_LC_COMMANDS_H
