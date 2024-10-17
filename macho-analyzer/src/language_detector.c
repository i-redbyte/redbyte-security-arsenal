#include "language_detector.h"
#include <string.h>
#include <stdlib.h>
#include <mach-o/nlist.h>
#include <stdio.h>

typedef struct {
    char detected_language_by_symbols[64];
    char detected_compiler_by_symbols[64];
    char detected_language_by_sections[64];
    char detected_compiler_by_sections[64];
    char detected_language_by_strings[64];
    char detected_compiler_by_strings[64];
    char final_language[64];
    char final_compiler[64];
} DetectionResults;


typedef struct {
    const char *prefix;
    const char *language;
    const char *compiler;
} SymbolMapping;

static const SymbolMapping symbol_mappings[] = {
        {"__Z",       "C++",           "Clang"},
        {"_OBJC_",    "Objective-C",   "Clang"},
        {"_$s",       "Swift",         "Apple Swift Compiler"},
        {"_$LT",      "Rust",          "rustc"},
        {"_main.",    "Go",            "gc (Go compiler)"},
        {"_Java",     "Java",          "GraalVM Native Image"},
        {"_JNI",      "Java",          "GraalVM Native Image"},
        {"_kfun:",    "Kotlin/Native", "Kotlin Native Compiler"},
        {"PyInit_",   "Python",        "Cython or CPython"},
        {"rb_",       "Ruby",          "Ruby Interpreter"},
        {"_ghczm",    "Haskell",       "GHC"},
        {"_erl_",     "Erlang/Elixir", "Erlang VM"},
        {"_elixir_",  "Elixir",        "Erlang VM"},
        {"_start",    "Assembly",      "Assembler"},
        {"_JS_",      "JavaScript",    "V8 or SpiderMonkey"},
        {"_PHP_",     "PHP",           "Zend Engine"},
        {"_perl_",    "Perl",          "Perl Interpreter"},
        {"_node_",    "Node.js",       "V8"},
        {"_v8_",      "V8",            "V8 Engine"},
        {"_julia_",   "Julia",         "Julia Compiler"},
        {"_matlab_",  "MATLAB",        "MATLAB Compiler"},
        {"_fortran_", "Fortran",       "GNU Fortran or Intel Fortran"},
        {"_cobol_",   "COBOL",         "COBOL Compiler"},
        {"_pascal_",  "Pascal",        "Free Pascal"},
        {"_ada_",     "Ada",           "GNAT"},
        {"_lisp_",    "Lisp",          "SBCL or CLISP"},
        {"_clojure_", "Clojure",       "Clojure Compiler"},
        {"_scheme_",  "Scheme",        "MIT/GNU Scheme"},
        {"_lua_",     "Lua",           "LuaJIT"},
        {"_tcl_",     "Tcl",           "Tcl Interpreter"},
        {"_r_",       "R",             "R Interpreter"},
        {"_ocaml_",   "OCaml",         "OCaml Compiler"},
        {"_scala_",   "Scala",         "Scala Compiler"},
        {"_elm_",     "Elm",           "Elm Compiler"},
        {"_dart_",    "Dart",          "Dart Compiler"},
        {"_crystal_", "Crystal",       "Crystal Compiler"},
        {"_nim_",     "Nim",           "Nim Compiler"},
        {"_zig_",     "Zig",           "Zig Compiler"}
};

/**
 * @brief Анализирует символы в Mach-O файле для определения языка и компилятора.
 *
 * Функция анализирует таблицу символов Mach-O файла, пытаясь распознать сигнатуры,
 * указывающие на используемый язык программирования и компилятор. Многие компиляторы и языки
 * создают специфичные символы (например, C++ использует mangled символы, Swift использует
 * префиксы _$s и т.д.), что позволяет точно определить их происхождение.
 *
 * @param mach_o_file Указатель на структуру MachOFile, содержащую информацию о командах загрузки
 *                    и секциях файла Mach-O.
 * @param file Указатель на открытый файл Mach-O для чтения таблицы символов и строк.
 *             Файл должен быть открыт на чтение.
 * @param lang_info Указатель на структуру LanguageInfo, в которую будет записана информация о языке
 *                  и компиляторе после анализа символов. Если символы указывают на конкретный язык
 *                  и компилятор, они будут записаны в соответствующие поля структуры.
 *
 * @return int Возвращает 0 при успешном определении языка и компилятора по символам, или -1, если
 *             символы не позволяют определить точный язык и компилятор.
 *
 * Примечания:
 * - Функция анализирует такие сигнатуры, как "_Z" для C++, "_OBJC_" для Objective-C, "_$s" для Swift и т.д.
 * - Если не удается определить язык или компилятор по символам, функция возвращает -1, и тогда
 *   другие методы анализа (например, анализ секций) могут быть использованы.
 */
static int analyze_symbols(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info);

/**
 * @brief Анализирует секции в Mach-O файле для определения языка и компилятора.
 *
 * Функция анализирует секции Mach-O файла, которые могут содержать специфичные данные для различных
 * языков программирования и компиляторов. Многие языки и компиляторы создают уникальные секции, такие как
 * `.gcc_except_table` для GCC, секции для Go, Swift, Rust и других языков, что позволяет определить язык
 * и компилятор.
 *
 * @param mach_o_file Указатель на структуру MachOFile, содержащую информацию о командах загрузки
 *                    и секциях файла Mach-O.
 * @param file Указатель на открытый файл Mach-O для чтения данных секций.
 *             Файл должен быть открыт на чтение.
 * @param lang_info Указатель на структуру LanguageInfo, в которую будет записана информация о языке
 *                  и компиляторе после анализа секций. Если определен специфичный для компилятора
 *                  или языка сегмент или секция, данные будут сохранены в lang_info.
 *
 * @return int Возвращает 0 при успешном определении языка и компилятора по секциям, или -1, если
 *             секции не позволяют сделать точное определение.
 *
 * Примечания:
 * - Функция проверяет такие секции, как `.gcc_except_table` для GCC, `__swift5_proto` для Swift,
 *   `__rodata` и другие для Go, и т.д.
 * - Если не удается определить язык или компилятор по секциям, функция возвращает -1, и тогда
 *   можно использовать другие методы анализа.
 */
static int analyze_sections(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info);

/**
 * @brief Анализирует строки данных в Mach-O файле для определения языка и компилятора.
 *
 * Функция анализирует строковые данные (например, константы) в секциях Mach-O файла,
 * которые могут содержать информацию о языке программирования или компиляторе. Многие компиляторы
 * и сборщики добавляют метаданные в виде строк, что может помочь определить, на каком языке
 * написана программа или какой компилятор использовался.
 *
 * @param mach_o_file Указатель на структуру MachOFile, содержащую информацию о командах загрузки
 *                    и секциях файла Mach-O.
 * @param file Указатель на открытый файл Mach-O для чтения строковых данных.
 *             Файл должен быть открыт на чтение.
 * @param lang_info Указатель на структуру LanguageInfo, в которую будет записана информация о языке
 *                  и компиляторе после анализа строк. Если найдены строки, специфичные для
 *                  определенного компилятора или языка, они будут записаны в lang_info.
 *
 * @return int Возвращает 0 при успешном определении языка и компилятора по строкам, или -1, если
 *             строки не содержат необходимой информации для точного определения.
 *
 * Примечания:
 * - Функция анализирует строковые данные, такие как строки Go build ID, Java JNI, строки,
 *   связанные с Python, и т.д.
 * - Если строки не позволяют определить язык или компилятор, функция возвращает -1,
 *   и тогда другие методы анализа могут быть использованы.
 */
static int analyze_strings(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info);


static void combine_results(DetectionResults *results);

int detect_language_and_compiler(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info) {
    if (!mach_o_file || !file || !lang_info) {
        fprintf(stderr, "Invalid arguments to detect_language_and_compiler\n");
        return -1;
    }

    DetectionResults results = {0};
    strcpy(results.detected_language_by_symbols, "Unknown");
    strcpy(results.detected_compiler_by_symbols, "Unknown");
    strcpy(results.detected_language_by_sections, "Unknown");
    strcpy(results.detected_compiler_by_sections, "Unknown");
    strcpy(results.detected_language_by_strings, "Unknown");
    strcpy(results.detected_compiler_by_strings, "Unknown");
    strcpy(results.final_language, "Unknown");
    strcpy(results.final_compiler, "Unknown");

    LanguageInfo temp_lang_info = {0};

    if (analyze_symbols(mach_o_file, file, &temp_lang_info) == 0) {
        strcpy(results.detected_language_by_symbols, temp_lang_info.language);
        strcpy(results.detected_compiler_by_symbols, temp_lang_info.compiler);
    }

    if (analyze_sections(mach_o_file, file, &temp_lang_info) == 0) {
        strcpy(results.detected_language_by_sections, temp_lang_info.language);
        strcpy(results.detected_compiler_by_sections, temp_lang_info.compiler);
    }

    if (analyze_strings(mach_o_file, file, &temp_lang_info) == 0) {
        strcpy(results.detected_language_by_strings, temp_lang_info.language);
        strcpy(results.detected_compiler_by_strings, temp_lang_info.compiler);
    }

    combine_results(&results);

    strcpy(lang_info->language, results.final_language);
    strcpy(lang_info->compiler, results.final_compiler);

    return 0;
}

static int analyze_symbols(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info) {
    struct symtab_command *symtab_cmd = NULL;
    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->command_count;

    // Поиск команды LC_SYMTAB
    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *) cmd;
            break;
        }
        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
    }

    if (!symtab_cmd || symtab_cmd->nsyms == 0) {
        return -1;
    }

    long current_offset = ftell(file);

    size_t symbol_size = mach_o_file->is_64_bit ? sizeof(struct nlist_64) : sizeof(struct nlist);
    size_t symbols_size = symtab_cmd->nsyms * symbol_size;

    void *symbols = malloc(symbols_size);
    if (!symbols) {
        fseek(file, current_offset, SEEK_SET);
        return -1;
    }

    fseek(file, symtab_cmd->symoff, SEEK_SET);
    if (fread(symbols, symbol_size, symtab_cmd->nsyms, file) != symtab_cmd->nsyms) {
        free(symbols);
        fseek(file, current_offset, SEEK_SET);
        return -1;
    }

    char *string_table = malloc(symtab_cmd->strsize);
    if (!string_table) {
        free(symbols);
        fseek(file, current_offset, SEEK_SET);
        return -1;
    }

    fseek(file, symtab_cmd->stroff, SEEK_SET);
    if (fread(string_table, 1, symtab_cmd->strsize, file) != symtab_cmd->strsize) {
        free(symbols);
        free(string_table);
        fseek(file, current_offset, SEEK_SET);
        return -1;
    }

    for (uint32_t i = 0; i < symtab_cmd->nsyms; i++) {
        char *sym_name;
        if (mach_o_file->is_64_bit) {
            struct nlist_64 *sym = &((struct nlist_64 *) symbols)[i];
            uint32_t strx = sym->n_un.n_strx;
            if (strx >= symtab_cmd->strsize) continue;
            sym_name = string_table + strx;
        } else {
            struct nlist *sym = &((struct nlist *) symbols)[i];
            uint32_t strx = sym->n_un.n_strx;
            if (strx >= symtab_cmd->strsize) continue;
            sym_name = string_table + strx;
        }

        // Проверка символа на принадлежность языку
        for (size_t j = 0; j < sizeof(symbol_mappings) / sizeof(SymbolMapping); j++) {
            if (strstr(sym_name, symbol_mappings[j].prefix) == sym_name) {
                strcpy(lang_info->language, symbol_mappings[j].language);
                strcpy(lang_info->compiler, symbol_mappings[j].compiler);
                free(symbols);
                free(string_table);
                fseek(file, current_offset, SEEK_SET);
                return 0;
            }
        }

        // Специальная проверка на компиляторы C: Clang, GCC и т.д.
        if (strcmp(sym_name, "_main") == 0 || strcmp(sym_name, "__start") == 0) {
            // Если обнаружен символ main, то это C, но нужно определить компилятор
            if (strstr(sym_name, "__gccmain")) {
                strcpy(lang_info->language, "C");
                strcpy(lang_info->compiler, "GCC");
            } else {
                strcpy(lang_info->language, "C");
                strcpy(lang_info->compiler, "Clang");
            }
            free(symbols);
            free(string_table);
            fseek(file, current_offset, SEEK_SET);
            return 0;
        }

        // NASM и FASM (зависит от символов и структуры файла)
        if (strstr(sym_name, "_start") == sym_name || strstr(sym_name, "nasm") == sym_name) {
            strcpy(lang_info->language, "Assembly");
            strcpy(lang_info->compiler, "NASM");
            free(symbols);
            free(string_table);
            fseek(file, current_offset, SEEK_SET);
            return 0;
        }
        if (strstr(sym_name, "_fasm_") == sym_name) {
            strcpy(lang_info->language, "Assembly");
            strcpy(lang_info->compiler, "FASM");
            free(symbols);
            free(string_table);
            fseek(file, current_offset, SEEK_SET);
            return 0;
        }
    }

    free(symbols);
    free(string_table);
    fseek(file, current_offset, SEEK_SET);

    return -1;
}

static int analyze_sections(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info) {
    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->command_count;

    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT || cmd->cmd == LC_SEGMENT_64) {
            uint32_t nsects;
            struct section *sections = NULL;

            if (cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg_cmd = (struct segment_command *) cmd;
                nsects = seg_cmd->nsects;
                sections = (struct section *) (seg_cmd + 1);
            } else {
                struct segment_command_64 *seg_cmd = (struct segment_command_64 *) cmd;
                nsects = seg_cmd->nsects;
                sections = (struct section *) (seg_cmd + 1);
            }

            for (uint32_t j = 0; j < nsects; j++) {
                char *sectname = sections[j].sectname;
                char *segname = sections[j].segname;

                // Определение компилятора GCC по специальной секции
                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, ".gcc_except_table") == 0) {
                    strcpy(lang_info->language, "C");
                    strcpy(lang_info->compiler, "GCC");
                    return 0;
                }

                // Определение NASM по специфичной секции
                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__nasm") == 0) {
                    strcpy(lang_info->language, "Assembly");
                    strcpy(lang_info->compiler, "NASM");
                    return 0;
                }

                // Определение FASM по специфичной секции
                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__fasm") == 0) {
                    strcpy(lang_info->language, "Assembly");
                    strcpy(lang_info->compiler, "FASM");
                    return 0;
                }

                // Определение языка Go по секциям
                if (strcmp(segname, "__TEXT") == 0 && (strcmp(sectname, "__rodata") == 0 ||
                                                       strcmp(sectname, "__typelink") == 0 ||
                                                       strcmp(sectname, "__itablink") == 0)) {
                    strcpy(lang_info->language, "Go");
                    strcpy(lang_info->compiler, "gc (Go compiler)");
                    return 0;
                }

                // Определение языка Rust по секциям
                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__rustc") == 0) {
                    strcpy(lang_info->language, "Rust");
                    strcpy(lang_info->compiler, "rustc");
                    return 0;
                }

                // Определение языка Swift по секциям
                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__swift5_proto") == 0) {
                    strcpy(lang_info->language, "Swift");
                    strcpy(lang_info->compiler, "Apple Swift Compiler");
                    return 0;
                }

                // Определение языка Kotlin по секциям
                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__kotlin") == 0) {
                    strcpy(lang_info->language, "Kotlin/Native");
                    strcpy(lang_info->compiler, "Kotlin Native Compiler");
                    return 0;
                }

                // Определение языка Haskell по секциям
                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__haskell_cr") == 0) {
                    strcpy(lang_info->language, "Haskell");
                    strcpy(lang_info->compiler, "GHC");
                    return 0;
                }

                // Определение Erlang/Elixir по секциям
                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__erlang_atom_tab") == 0) {
                    strcpy(lang_info->language, "Erlang/Elixir");
                    strcpy(lang_info->compiler, "Erlang VM");
                    return 0;
                }

                // Определение языка Assembly по минимальному числу команд загрузки
                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__text") == 0 && mach_o_file->command_count <= 5) {
                    strcpy(lang_info->language, "Assembly");
                    strcpy(lang_info->compiler, "Assembler");
                    return 0;
                }
            }
        }

        // Переход к следующей команде загрузки
        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
    }

    return -1; // Если не удалось определить язык или компилятор по секциям
}

static int analyze_strings(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info) {
    long current_offset = ftell(file);

    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->command_count;

    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT || cmd->cmd == LC_SEGMENT_64) {
            uint32_t nsects;
            struct section *sections = NULL;

            if (cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg_cmd = (struct segment_command *) cmd;
                nsects = seg_cmd->nsects;
                sections = (struct section *) (seg_cmd + 1);
            } else {
                struct segment_command_64 *seg_cmd = (struct segment_command_64 *) cmd;
                nsects = seg_cmd->nsects;
                sections = (struct section *) (seg_cmd + 1);
            }

            for (uint32_t j = 0; j < nsects; j++) {
                char *sectname = sections[j].sectname;
                char *segname = sections[j].segname;

                if (strcmp(segname, "__TEXT") == 0 &&
                    (strcmp(sectname, "__cstring") == 0 || strcmp(sectname, "__const") == 0)) {
                    uint32_t offset = sections[j].offset;
                    uint32_t size = sections[j].size;

                    char *data = malloc(size);
                    if (!data) continue;

                    fseek(file, offset, SEEK_SET);
                    if (fread(data, 1, size, file) != size) {
                        free(data);
                        continue;
                    }

                    if (strstr(data, "go.buildid") || strstr(data, "Go build ID")) {
                        strcpy(lang_info->language, "Go");
                        strcpy(lang_info->compiler, "gc (Go compiler)");
                        free(data);
                        fseek(file, current_offset, SEEK_SET);
                        return 0;
                    }

                    if (strstr(data, "Python") || strstr(data, "Py_InitModule")) {
                        strcpy(lang_info->language, "Python");
                        strcpy(lang_info->compiler, "Cython or CPython");
                        free(data);
                        fseek(file, current_offset, SEEK_SET);
                        return 0;
                    }

                    if (strstr(data, "Java") || strstr(data, "JNI")) {
                        strcpy(lang_info->language, "Java");
                        strcpy(lang_info->compiler, "GraalVM Native Image");
                        free(data);
                        fseek(file, current_offset, SEEK_SET);
                        return 0;
                    }

                    if (strstr(data, "Kotlin") || strstr(data, "kotlin.native.internal")) {
                        strcpy(lang_info->language, "Kotlin/Native");
                        strcpy(lang_info->compiler, "Kotlin Native Compiler");
                        free(data);
                        fseek(file, current_offset, SEEK_SET);
                        return 0;
                    }

                    free(data);
                }
            }
        }
        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
    }

    fseek(file, current_offset, SEEK_SET);
    return -1;
}

static void combine_results(DetectionResults *results) {
    if (!results) {
        fprintf(stderr, "Invalid arguments to combine_results\n");
        return;
    }

    if (strcmp(results->detected_language_by_symbols, results->detected_language_by_sections) == 0 &&
        strcmp(results->detected_language_by_sections, results->detected_language_by_strings) == 0 &&
        strcmp(results->detected_language_by_symbols, "Unknown") != 0) {
        strcpy(results->final_language, results->detected_language_by_symbols);
        strcpy(results->final_compiler, results->detected_compiler_by_symbols);
    } else if (strcmp(results->detected_language_by_symbols, results->detected_language_by_sections) == 0 &&
               strcmp(results->detected_language_by_symbols, "Unknown") != 0) {
        strcpy(results->final_language, results->detected_language_by_symbols);
        strcpy(results->final_compiler, results->detected_compiler_by_symbols);
        fprintf(stderr, "Warning: String analysis does not match symbol and section analysis.\n");
    } else if (strcmp(results->detected_language_by_symbols, results->detected_language_by_strings) == 0 &&
               strcmp(results->detected_language_by_symbols, "Unknown") != 0) {
        strcpy(results->final_language, results->detected_language_by_symbols);
        strcpy(results->final_compiler, results->detected_compiler_by_symbols);
        fprintf(stderr, "Warning: Section analysis does not match symbol and string analysis.\n");
    } else if (strcmp(results->detected_language_by_sections, results->detected_language_by_strings) == 0 &&
               strcmp(results->detected_language_by_sections, "Unknown") != 0) {
        strcpy(results->final_language, results->detected_language_by_sections);
        strcpy(results->final_compiler, results->detected_compiler_by_sections);
        fprintf(stderr, "Warning: Symbol analysis does not match section and string analysis.\n");
    } else if (strcmp(results->detected_language_by_symbols, "Unknown") != 0) {
        strcpy(results->final_language, results->detected_language_by_symbols);
        strcpy(results->final_compiler, results->detected_compiler_by_symbols);
    } else if (strcmp(results->detected_language_by_sections, "Unknown") != 0) {
        strcpy(results->final_language, results->detected_language_by_sections);
        strcpy(results->final_compiler, results->detected_compiler_by_sections);
    } else if (strcmp(results->detected_language_by_strings, "Unknown") != 0) {
        strcpy(results->final_language, results->detected_language_by_strings);
        strcpy(results->final_compiler, results->detected_compiler_by_strings);
    } else {
        strcpy(results->final_language, "Unknown");
        strcpy(results->final_compiler, "Unknown");
    }
}