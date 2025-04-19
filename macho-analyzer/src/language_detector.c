#include "language_detector.h"
#include <string.h>
#include <stdlib.h>
#include <mach-o/nlist.h>
#include <stdio.h>

typedef struct {
    const char *segment_name;
    const char *section_name;
    const char *language;
    const char *compiler;
} SectionMapping;

static const SectionMapping section_mappings[] = {
        // C и компиляторы
        {"__TEXT", "__cstring",               "C",             "Clang"},
        {"__DATA", "__data",                  "C",             "Clang"},
        {"__TEXT", "__unwind_info",           "C",             "Clang"},
        {"__DATA", "__data",                  "C",             "GCC"},

        // C++
        {"__TEXT", ".gcc_except_table",       "C++",           "GCC"},
        {"__TEXT", "__const",                 "C++",           "Clang"},
        {"__TEXT", "__cstring",               "C++",           "Clang"},
        {"__DATA", "__const",                 "C++",           "Clang"},
        {"__TEXT", "__ZTI",                   "C++",           "Clang"}, // RTTI info
        {"__TEXT", "__static_init",           "C++",           "Clang"},

        // Objective-C
        {"__DATA", "__objc_classlist",        "Objective-C",   "Clang"},
        {"__DATA", "__objc_selrefs",          "Objective-C",   "Clang"},
        {"__TEXT", "__objc_methname",         "Objective-C",   "Clang"},
        {"__TEXT", "__objc_const",            "Objective-C",   "Clang"},
        {"__TEXT", "__objc_classname",        "Objective-C",   "Clang"},
        {"__DATA", "__objc_const",            "Objective-C",   "Clang"},

        // Swift
        {"__TEXT", "__swift5_proto",          "Swift",         "Apple Swift Compiler"},
        {"__TEXT", "__swift5_types",          "Swift",         "Apple Swift Compiler"},
        {"__TEXT", "__swift5_fieldmd",        "Swift",         "Apple Swift Compiler"},
        {"__TEXT", "__swift5_assocty",        "Swift",         "Apple Swift Compiler"},
        {"__TEXT", "__swift5_replace",        "Swift",         "Apple Swift Compiler"},
        {"__TEXT", "__swift5_builtin",        "Swift",         "Apple Swift Compiler"},
        {"__TEXT", "__swift5_capture",        "Swift",         "Apple Swift Compiler"},

        // Go
        {"__TEXT", "__rodata",                "Go",            "gc (Go compiler)"},
        {"__TEXT", "__typelink",              "Go",            "gc (Go compiler)"},
        {"__TEXT", "__itablink",              "Go",            "gc (Go compiler)"},
        {"__DATA", "__go_buildinfo",          "Go",            "gc (Go compiler)"},
        {"__TEXT", "__gosymtab",              "Go",            "gc (Go compiler)"},
        {"__TEXT", "__gopclntab",             "Go",            "gc (Go compiler)"},

        // Rust
        {"__TEXT", "__rustc",                 "Rust",          "rustc"},
        {"__DATA", "__rust_extern_crate_map", "Rust",          "rustc"},
        {"__TEXT", "__llvm_prf_names",        "Rust",          "rustc"},
        {"__DATA", "__llvm_prf_cnts",         "Rust",          "rustc"},

        // Assembly
        {"__TEXT", "__text",                  "Assembly",      "Assembler"},

        // Kotlin/Native
        {"__TEXT", "__kotlin",                "Kotlin/Native", "Kotlin Native Compiler"},
        {"__DATA", "__kotlin_metadata",       "Kotlin/Native", "Kotlin Native Compiler"},

        // Haskell
        {"__TEXT", "__stginit",               "Haskell",       "GHC"},
        {"__TEXT", "__hs_info",               "Haskell",       "GHC"},
        {"__DATA", "__hs_data",               "Haskell",       "GHC"},
        {"__TEXT", "__hs_lct",                "Haskell",       "GHC"},

        // Erlang/Elixir
        {"__TEXT", "__erlang_atom_tab",       "Erlang",        "Erlang VM"},
        {"__DATA", "__erlang_module_info",    "Erlang",        "Erlang VM"},
        {"__TEXT", "__elixir_module_info",    "Elixir",        "Erlang VM"},

        // Java (GraalVM Native Image)
        {"__TEXT", "__graalvm",               "Java",          "GraalVM Native Image"},
        {"__DATA", "__graalvm_data",          "Java",          "GraalVM Native Image"},

        // LuaJIT
        {"__TEXT", "__luajit_bc",             "Lua",           "LuaJIT Compiler"},
        {"__TEXT", "__luajit",                "Lua",           "LuaJIT Compiler"},
        {"__DATA", "__luajit_data",           "Lua",           "LuaJIT Compiler"},

        // Ruby
        {"__TEXT", "__ruby",                  "Ruby",          "Ruby Interpreter"},
        {"__DATA", "__ruby_symbols",          "Ruby",          "Ruby Interpreter"},
        {"__TEXT", "__rb_funcall",            "Ruby",          "Ruby Interpreter"},
        {"__DATA", "__rb_symbols",            "Ruby",          "Ruby Interpreter"},

        // D
        {"__TEXT", "__dmd_gc",                "D",             "DMD"},
        {"__DATA", "__dmd_data",              "D",             "DMD"},
        {"__TEXT", "__dmd_script",            "D",             "DMD"},
        {"__DATA", "__dmd_tls",               "D",             "DMD"},

        // Nim
        {"__TEXT", "__nimrod",                "Nim",           "Nim Compiler"},
        {"__DATA", "__nimdata",               "Nim",           "Nim Compiler"},
        {"__TEXT", "__nimrtl",                "Nim",           "Nim Compiler"},
        {"__DATA", "__nimtls",                "Nim",           "Nim Compiler"},

        // OCaml
        {"__TEXT", "__caml_code",             "OCaml",         "OCaml Compiler"},
        {"__DATA", "__caml_globals",          "OCaml",         "OCaml Compiler"},

        // Crystal
        {"__TEXT", "__crystal",               "Crystal",       "Crystal Compiler"},
        {"__DATA", "__crystal_data",          "Crystal",       "Crystal Compiler"},
        {"__TEXT", "__crystal_init",          "Crystal",       "Crystal Compiler"},
        {"__DATA", "__crystal_globals",       "Crystal",       "Crystal Compiler"},

        // Zig
        {"__TEXT", "__zig",                   "Zig",           "Zig Compiler"},
        {"__DATA", "__zig_data",              "Zig",           "Zig Compiler"},
        {"__TEXT", "__zig_strings",           "Zig",           "Zig Compiler"},
        {"__DATA", "__zig_globals",           "Zig",           "Zig Compiler"},

        // Julia
        {"__TEXT", "__julia",                 "Julia",         "Julia Compiler"},
        {"__DATA", "__julia_data",            "Julia",         "Julia Compiler"},
        {"__TEXT", "__julia_fns",             "Julia",         "Julia Compiler"},
        {"__DATA", "__julia_consts",          "Julia",         "Julia Compiler"},

        // Lisp (SBCL)
        {"__TEXT", "__sbcl_text",             "Common Lisp",   "SBCL"},
        {"__DATA", "__sbcl_data",             "Common Lisp",   "SBCL"},

        // Scala Native
        {"__TEXT", "__scala_entry",           "Scala",         "Scala Native"},
        {"__DATA", "__scala_data",            "Scala",         "Scala Native"},
        {"__TEXT", "__scalanative_func",      "Scala",         "Scala Native"},
        {"__DATA", "__scalanative_data",      "Scala",         "Scala Native"}
};

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
        // C++
        {"_Z",         "C++",           "GCC or Clang"},
        {"_ZN",        "C++",           "GCC or Clang"},
        {"_ZSt",       "C++",           "Standard C++ Library"},
        {"_ZT",        "C++",           "GCC or Clang"}, // RTTI информация

        // Objective-C
        {"_OBJC_",     "Objective-C",   "Clang"},
        {"_objc_",     "Objective-C",   "Clang"},

        // Swift
        {"_$s",        "Swift",         "Apple Swift Compiler"},

        // Rust
        {"_R",         "Rust",          "rustc"},

        // Go
        {"_main.",     "Go",            "gc (Go compiler)"},
        {"_runtime.",  "Go",            "gc (Go compiler)"},

        // Java (JNI)
        {"Java_",      "Java",          "JNI"},

        // Kotlin/Native
        {"kfun:",      "Kotlin/Native", "Kotlin Native Compiler"},

        // Python
        {"PyInit_",    "Python",        "Cython or CPython"},
        {"Py",         "Python",        "CPython"},

        // Ruby
        {"rb_",        "Ruby",          "Ruby Interpreter"},

        // Haskell
        {"_ghczm",     "Haskell",       "GHC"},

        // Erlang
        {"erl_",       "Erlang",        "Erlang VM"},

        // Elixir
        {"Elixir.",    "Elixir",        "Elixir Compiler"},

        // Perl
        {"Perl_",      "Perl",          "Perl Interpreter"},

        // Lua
        {"lua_",       "Lua",           "Lua Interpreter or LuaJIT"},

        // R
        {"Rf_",        "R",             "R Interpreter"},
        {"R_",         "R",             "R Interpreter"},

        // OCaml
        {"caml",       "OCaml",         "OCaml Compiler"},

        // D
        {"_D",         "D",             "DMD or LDC"},

        // Julia
        {"jl_",        "Julia",         "Julia Compiler"},

        // Fortran
        {"_gfortran",  "Fortran",       "GNU Fortran"},
        {"_fortran",   "Fortran",       "Intel Fortran"},

        // Pascal
        {"FPC_",       "Pascal",        "Free Pascal Compiler"},

        // Ada
        {"__ada_",     "Ada",           "GNAT"},

        // Crystal
        {"__crystal_", "Crystal",       "Crystal Compiler"},

        // Nim
        {"nim",        "Nim",           "Nim Compiler"},

        // Zig
        {"zig_",       "Zig",           "Zig Compiler"},

        // Dart
        {"Dart_",      "Dart",          "Dart Compiler"},

        // Common Lisp
        {"cl_",        "Common Lisp",   "SBCL or CLISP"},

        // Scala
        {"_Z7scala",   "Scala",         "Scala Native"},

        // Tcl
        {"Tcl_",       "Tcl",           "Tcl Interpreter"},

        // Assembly
        {"_start",     "Assembly",      "Assembler"}, // Вниз для предотвращения ложных срабатываний

        // Дополнительные ассемблеры
        {"nasm_",      "Assembly",      "NASM"},
        {"fasm_",      "Assembly",      "FASM"}
};

/**
 * Анализирует символы в Mach-O файле для определения языка и компилятора.
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 * @param file Указатель на открытый файл Mach-O.
 * @param lang_info Указатель на структуру LanguageInfo для записи результатов.
 * @return 0 при успехе, -1 при ошибке.
 */
static int analyze_symbols(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info);

/**
 * Анализирует секции в Mach-O файле для определения языка и компилятора.
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 * @param lang_info Указатель на структуру LanguageInfo для записи результатов.
 * @return 0 при успехе, -1 при ошибке.
 */
static int analyze_sections(const MachOFile *mach_o_file, LanguageInfo *lang_info);

/**
 * Анализирует строки данных в Mach-O файле для определения языка и компилятора.
 *
 * @param mach_o_file Указатель на структуру MachOFile.
 * @param file Указатель на открытый файл Mach-O.
 * @param lang_info Указатель на структуру LanguageInfo для записи результатов.
 * @return 0 при успехе, -1 при ошибке.
 */
static int analyze_strings(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info);

/**
 * Проверяет секцию на соответствие языку и компилятору.
 *
 * @param segname Имя сегмента.
 * @param sectname Имя секции.
 * @param lang_info Указатель на структуру LanguageInfo для записи результатов.
 * @return 0 при совпадении, -1 если не найдено.
 */
static int check_section(const char *segname, const char *sectname, LanguageInfo *lang_info);

/**
 * Объединяет результаты анализа символов, секций и строк.
 *
 * @param results Указатель на структуру DetectionResults.
 */
static void combine_results(DetectionResults *results);

int detect_language_and_compiler(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info) {
    if (!mach_o_file || !file || !lang_info) {
        fprintf(stderr, "Ошибка: Неверные аргументы в detect_language_and_compiler\n");
        return -1;
    }

    DetectionResults results = {0};
    strcpy(results.detected_language_by_symbols, "Неизвестно");
    strcpy(results.detected_compiler_by_symbols, "Неизвестно");
    strcpy(results.detected_language_by_sections, "Неизвестно");
    strcpy(results.detected_compiler_by_sections, "Неизвестно");
    strcpy(results.detected_language_by_strings, "Неизвестно");
    strcpy(results.detected_compiler_by_strings, "Неизвестно");
    strcpy(results.final_language, "Неизвестно");
    strcpy(results.final_compiler, "Неизвестно");

    LanguageInfo temp_lang_info = {0};

    if (analyze_symbols(mach_o_file, file, &temp_lang_info) == 0) {
        strcpy(results.detected_language_by_symbols, temp_lang_info.language);
        strcpy(results.detected_compiler_by_symbols, temp_lang_info.compiler);
    }

    if (analyze_sections(mach_o_file, &temp_lang_info) == 0) {
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
    if (!mach_o_file || !file || !lang_info) {
        fprintf(stderr, "Ошибка: Неверные аргументы в analyze_symbols\n");
        return -1;
    }

    struct symtab_command *symtab_cmd = NULL;
    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->load_command_count; // Исправлено: command_count -> load_command_count

    // Поиск команды LC_SYMTAB
    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cmd;
            break;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    if (!symtab_cmd || symtab_cmd->nsyms == 0) {
        return -1;
    }

    long current_offset = ftell(file);

    size_t symbol_size = mach_o_file->is_64_bit ? sizeof(struct nlist_64) : sizeof(struct nlist);
    size_t symbols_size = symtab_cmd->nsyms * symbol_size;

    void *symbols = malloc(symbols_size);
    if (!symbols) {
        fprintf(stderr, "Ошибка: Не удалось выделить память для символов\n");
        fseek(file, current_offset, SEEK_SET);
        return -1;
    }

    fseek(file, symtab_cmd->symoff, SEEK_SET);
    if (fread(symbols, symbol_size, symtab_cmd->nsyms, file) != symtab_cmd->nsyms) {
        fprintf(stderr, "Ошибка: Не удалось прочитать символы\n");
        free(symbols);
        fseek(file, current_offset, SEEK_SET);
        return -1;
    }

    char *string_table = malloc(symtab_cmd->strsize);
    if (!string_table) {
        fprintf(stderr, "Ошибка: Не удалось выделить память для таблицы строк\n");
        free(symbols);
        fseek(file, current_offset, SEEK_SET);
        return -1;
    }

    fseek(file, symtab_cmd->stroff, SEEK_SET);
    if (fread(string_table, 1, symtab_cmd->strsize, file) != symtab_cmd->strsize) {
        fprintf(stderr, "Ошибка: Не удалось прочитать таблицу строк\n");
        free(symbols);
        free(string_table);
        fseek(file, current_offset, SEEK_SET);
        return -1;
    }

    for (uint32_t i = 0; i < symtab_cmd->nsyms; i++) {
        char *sym_name;
        if (mach_o_file->is_64_bit) {
            struct nlist_64 *sym = &((struct nlist_64 *)symbols)[i];
            uint32_t strx = sym->n_un.n_strx;
            if (strx >= symtab_cmd->strsize) continue;
            sym_name = string_table + strx;
        } else {
            struct nlist *sym = &((struct nlist *)symbols)[i];
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

static int check_section(const char *segname, const char *sectname, LanguageInfo *lang_info) {
    for (size_t i = 0; i < sizeof(section_mappings) / sizeof(SectionMapping); i++) {
        if (strcmp(segname, section_mappings[i].segment_name) == 0 &&
            strcmp(sectname, section_mappings[i].section_name) == 0) {
            strcpy(lang_info->language, section_mappings[i].language);
            strcpy(lang_info->compiler, section_mappings[i].compiler);
            return 0;
        }
    }
    return -1;
}

static int analyze_sections(const MachOFile *mach_o_file, LanguageInfo *lang_info) {
    if (!mach_o_file || !lang_info) {
        fprintf(stderr, "Ошибка: Неверные аргументы в analyze_sections\n");
        return -1;
    }

    strcpy(lang_info->language, "Неизвестно");
    strcpy(lang_info->compiler, "Неизвестно");

    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->load_command_count; // Исправлено: command_count -> load_command_count

    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmdsize == 0) {
            fprintf(stderr, "Ошибка: Неверный размер команды загрузки\n");
            return -1;
        }

        if (cmd->cmd == LC_SEGMENT || cmd->cmd == LC_SEGMENT_64) {
            uint32_t nsects = 0;
            void *sections = NULL;

            if (cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg_cmd = (struct segment_command *)cmd;
                nsects = seg_cmd->nsects;
                sections = (void *)(seg_cmd + 1);
            } else { // LC_SEGMENT_64
                struct segment_command_64 *seg_cmd = (struct segment_command_64 *)cmd;
                nsects = seg_cmd->nsects;
                sections = (void *)(seg_cmd + 1);
            }

            // Проверка корректности числа секций
            if (nsects == 0 || sections == NULL) {
                cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
                continue;
            }

            for (uint32_t j = 0; j < nsects; j++) {
                char segname[17] = {0};
                char sectname[17] = {0};

                if (cmd->cmd == LC_SEGMENT) {
                    struct section *section = &((struct section *)sections)[j];
                    memcpy(segname, section->segname, 16);
                    segname[16] = '\0';
                    memcpy(sectname, section->sectname, 16);
                    sectname[16] = '\0';
                } else { // LC_SEGMENT_64
                    struct section_64 *section = &((struct section_64 *)sections)[j];
                    memcpy(segname, section->segname, 16);
                    segname[16] = '\0';
                    memcpy(sectname, section->sectname, 16);
                    sectname[16] = '\0';
                }

                if (check_section(segname, sectname, lang_info) == 0) {
                    return 0;
                }

                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__text") == 0 &&
                    mach_o_file->load_command_count <= 5) { // Исправлено: command_count -> load_command_count
                    strcpy(lang_info->language, "Assembly");
                    strcpy(lang_info->compiler, "Assembler");
                    return 0;
                }
            }
        }

        if (cmd->cmdsize == 0) {
            fprintf(stderr, "Ошибка: Обнаружен неверный размер команды, предотвращение бесконечного цикла\n");
            return -1;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    return -1;
}

static int analyze_strings(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info) {
    if (!mach_o_file || !file || !lang_info) {
        fprintf(stderr, "Ошибка: Неверные аргументы в analyze_strings\n");
        return -1;
    }

    long current_offset = ftell(file);

    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->load_command_count; // Исправлено: command_count -> load_command_count

    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT || cmd->cmd == LC_SEGMENT_64) {
            uint32_t nsects;
            struct section *sections = NULL;

            if (cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg_cmd = (struct segment_command *)cmd;
                nsects = seg_cmd->nsects;
                sections = (struct section *)(seg_cmd + 1);
            } else {
                struct segment_command_64 *seg_cmd = (struct segment_command_64 *)cmd;
                nsects = seg_cmd->nsects;
                sections = (struct section *)(seg_cmd + 1);
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
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    fseek(file, current_offset, SEEK_SET);
    return -1;
}

static void combine_results(DetectionResults *results) {
    if (!results) {
        fprintf(stderr, "Ошибка: Неверные аргументы в combine_results\n");
        return;
    }

    if (strcmp(results->detected_language_by_symbols, results->detected_language_by_sections) == 0 &&
        strcmp(results->detected_language_by_sections, results->detected_language_by_strings) == 0 &&
        strcmp(results->detected_language_by_symbols, "Неизвестно") != 0) {
        strcpy(results->final_language, results->detected_language_by_symbols);
        strcpy(results->final_compiler, results->detected_compiler_by_symbols);
    } else if (strcmp(results->detected_language_by_symbols, results->detected_language_by_sections) == 0 &&
               strcmp(results->detected_language_by_symbols, "Неизвестно") != 0) {
        strcpy(results->final_language, results->detected_language_by_symbols);
        strcpy(results->final_compiler, results->detected_compiler_by_symbols);
        fprintf(stderr, "Предупреждение: Анализ строк не совпадает с анализом символов и секций.\n");
    } else if (strcmp(results->detected_language_by_symbols, results->detected_language_by_strings) == 0 &&
               strcmp(results->detected_language_by_symbols, "Неизвестно") != 0) {
        strcpy(results->final_language, results->detected_language_by_symbols);
        strcpy(results->final_compiler, results->detected_compiler_by_symbols);
        fprintf(stderr, "Предупреждение: Анализ секций не совпадает с анализом символов и строк.\n");
    } else if (strcmp(results->detected_language_by_sections, results->detected_language_by_strings) == 0 &&
               strcmp(results->detected_language_by_sections, "Неизвестно") != 0) {
        strcpy(results->final_language, results->detected_language_by_sections);
        strcpy(results->final_compiler, results->detected_compiler_by_sections);
        fprintf(stderr, "Предупреждение: Анализ символов не совпадает с анализом секций и строк.\n");
    } else if (strcmp(results->detected_language_by_symbols, "Неизвестно") != 0) {
        strcpy(results->final_language, results->detected_language_by_symbols);
        strcpy(results->final_compiler, results->detected_compiler_by_symbols);
    } else if (strcmp(results->detected_language_by_sections, "Неизвестно") != 0) {
        strcpy(results->final_language, results->detected_language_by_sections);
        strcpy(results->final_compiler, results->detected_compiler_by_sections);
    } else if (strcmp(results->detected_language_by_strings, "Неизвестно") != 0) {
        strcpy(results->final_language, results->detected_language_by_strings);
        strcpy(results->final_compiler, results->detected_compiler_by_strings);
    } else {
        strcpy(results->final_language, "Неизвестно");
        strcpy(results->final_compiler, "Неизвестно");
    }
}