#ifndef LANGUAGE_DETECTOR_H
#define LANGUAGE_DETECTOR_H

#include "macho_analyzer.h"

typedef struct {
    char language[64];
    char compiler[64];
} LanguageInfo;

/**
 * @brief Определяет язык программирования и компилятор для Mach-O файла.
 *
 * Функция анализирует Mach-O файл для определения языка программирования и компилятора,
 * используемого для его создания. Для этого она использует информацию из символов и секций
 * Mach-O файла. Сначала анализируются символы, которые могут содержать специфичные сигнатуры,
 * указывающие на язык или компилятор. Затем анализируются секции, если символы не дали точного результата.
 *
 * @param mach_o_file Указатель на структуру MachOFile, содержащую информацию о файле.
 *                    Эта структура должна быть предварительно проанализирована и содержать
 *                    команды загрузки и секции.
 * @param file Указатель на открытый файл Mach-O для чтения данных, таких как символы и секции.
 *             Файл должен быть открыт на чтение.
 * @param lang_info Указатель на структуру LanguageInfo, в которой будет сохранена информация
 *                  о языке программирования и компиляторе после анализа.
 *                  В случае успешного определения, в эту структуру будет записано имя языка
 *                  (в поле `language`) и компилятора (в поле `compiler`).
 *
 * @return int Возвращает 0 при успешном определении языка и компилятора, или -1 в случае ошибки
 *             (например, если файл поврежден или структура MachOFile пуста).
 *
 * Примечания:
 * - Если не удается определить язык или компилятор, функция по умолчанию установит язык как
 *   "Assembly" и компилятор как "Assembler".
 * - Функция поддерживает множество языков и компиляторов, включая C, C++, Swift, Rust, Go,
 *   Java, Python, Ruby, Kotlin/Native, Haskell, Erlang/Elixir и другие.
 *
 * Пример использования:
 * @code
 * LanguageInfo lang_info;
 * if (detect_language_and_compiler(&mach_o_file, file, &lang_info) == 0) {
 *     printf("Language: %s\n", lang_info.language);
 *     printf("Compiler: %s\n", lang_info.compiler);
 * } else {
 *     printf("Failed to detect language and compiler information.\n");
 * }
 * @endcode
 */
int detect_language_and_compiler(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info);

#endif // LANGUAGE_DETECTOR_H
