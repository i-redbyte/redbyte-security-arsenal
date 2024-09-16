#include "language_detector.h"
#include <string.h>
#include <stdlib.h>
#include <mach-o/nlist.h>
#include <mach-o/stab.h>
#include <stdio.h>

static int analyze_symbols(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info);

static int analyze_sections(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info);

static int analyze_strings(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info);

int detect_language_and_compiler(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info) {
    if (!mach_o_file || !file || !lang_info) {
        return -1;
    }

    memset(lang_info, 0, sizeof(LanguageInfo));
    strcpy(lang_info->language, "Unknown");
    strcpy(lang_info->compiler, "Unknown");

    if (analyze_symbols(mach_o_file, file, lang_info) == 0) {
        return 0;
    }

    if (analyze_sections(mach_o_file, file, lang_info) == 0) {
        return 0;
    }

    if (analyze_strings(mach_o_file, file, lang_info) == 0) {
        return 0;
    }

    if (strcmp(lang_info->language, "Unknown") == 0) {
        strcpy(lang_info->language, "Assembly");
        strcpy(lang_info->compiler, "Assembler");
    }

    return 0;
}

static int analyze_symbols(const MachOFile *mach_o_file, FILE *file, LanguageInfo *lang_info) {
    struct symtab_command *symtab_cmd = NULL;
    struct load_command *cmd = mach_o_file->commands;
    uint32_t ncmds = mach_o_file->command_count;

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

    uint32_t cpp_symbols = 0;
    uint32_t objc_symbols = 0;
    uint32_t swift_symbols = 0;
    uint32_t rust_symbols = 0;
    uint32_t go_symbols = 0;
    uint32_t java_symbols = 0;
    uint32_t kotlin_symbols = 0;
    uint32_t python_symbols = 0;
    uint32_t ruby_symbols = 0;
    uint32_t haskell_symbols = 0;
    uint32_t erlang_symbols = 0;
    uint32_t assembly_symbols = 0;

    for (uint32_t i = 0; i < symtab_cmd->nsyms; i++) {
        char *sym_name;
        uint8_t n_type;
        if (mach_o_file->is_64_bit) {
            struct nlist_64 *sym = &((struct nlist_64 *) symbols)[i];
            uint32_t strx = sym->n_un.n_strx;
            if (strx >= symtab_cmd->strsize) continue;
            sym_name = string_table + strx;
            n_type = sym->n_type;
        } else {
            struct nlist *sym = &((struct nlist *) symbols)[i];
            uint32_t strx = sym->n_un.n_strx;
            if (strx >= symtab_cmd->strsize) continue;
            sym_name = string_table + strx;
            n_type = sym->n_type;
        }

        if (strstr(sym_name, "__Z") == sym_name || strstr(sym_name, "_Z") == sym_name) {
            cpp_symbols++;
        } else if (strstr(sym_name, "_OBJC_") || strstr(sym_name, "_objc_")) {
            objc_symbols++;
        } else if (strstr(sym_name, "_$s") == sym_name || strstr(sym_name, "_$S") == sym_name) {
            swift_symbols++;
        } else if (strstr(sym_name, "_$LT") || strstr(sym_name, "_ZN")) {
            rust_symbols++;
        } else if (strstr(sym_name, "_main.") == sym_name || strstr(sym_name, "_runtime.") == sym_name) {
            go_symbols++;
        } else if (strstr(sym_name, "_Java") == sym_name || strstr(sym_name, "_JNI") == sym_name) {
            java_symbols++;
        } else if (strstr(sym_name, "_kfun:") == sym_name) {
            kotlin_symbols++;
        } else if (strstr(sym_name, "PyInit_") == sym_name || strstr(sym_name, "_Py") == sym_name) {
            python_symbols++;
        } else if (strstr(sym_name, "rb_") == sym_name || strstr(sym_name, "_rb_") == sym_name) {
            ruby_symbols++;
        } else if (strstr(sym_name, "_ghczm") == sym_name || strstr(sym_name, "_stg") == sym_name) {
            haskell_symbols++;
        } else if (strstr(sym_name, "_erl_") == sym_name || strstr(sym_name, "_elixir_") == sym_name) {
            erlang_symbols++;
        } else if (strcmp(sym_name, "_start") == 0 || strcmp(sym_name, "start") == 0) {
            assembly_symbols++;
        }
    }

    uint32_t max_symbols = 0;
    const char *detected_language = NULL;
    const char *detected_compiler = NULL;

    if (swift_symbols > max_symbols) {
        max_symbols = swift_symbols;
        detected_language = "Swift";
        detected_compiler = "Apple Swift Compiler";
    }
    if (objc_symbols > max_symbols) {
        max_symbols = objc_symbols;
        detected_language = "Objective-C";
        detected_compiler = "Clang";
    }
    if (cpp_symbols > max_symbols) {
        max_symbols = cpp_symbols;
        detected_language = "C++";
        detected_compiler = "Clang";
    }
    if (rust_symbols > max_symbols) {
        max_symbols = rust_symbols;
        detected_language = "Rust";
        detected_compiler = "rustc";
    }
    if (go_symbols > max_symbols) {
        max_symbols = go_symbols;
        detected_language = "Go";
        detected_compiler = "gc (Go compiler)";
    }
    if (kotlin_symbols > max_symbols) {
        max_symbols = kotlin_symbols;
        detected_language = "Kotlin/Native";
        detected_compiler = "Kotlin Native Compiler";
    }
    if (java_symbols > max_symbols) {
        max_symbols = java_symbols;
        detected_language = "Java";
        detected_compiler = "GraalVM Native Image";
    }
    if (python_symbols > max_symbols) {
        max_symbols = python_symbols;
        detected_language = "Python";
        detected_compiler = "Cython or CPython";
    }
    if (ruby_symbols > max_symbols) {
        max_symbols = ruby_symbols;
        detected_language = "Ruby";
        detected_compiler = "Ruby Interpreter";
    }
    if (haskell_symbols > max_symbols) {
        max_symbols = haskell_symbols;
        detected_language = "Haskell";
        detected_compiler = "GHC";
    }
    if (erlang_symbols > max_symbols) {
        max_symbols = erlang_symbols;
        detected_language = "Erlang/Elixir";
        detected_compiler = "Erlang VM";
    }
    if (assembly_symbols > 0 && max_symbols == 0) {
        detected_language = "Assembly";
        detected_compiler = "Assembler";
    }

    if (detected_language) {
        strcpy(lang_info->language, detected_language);
        strcpy(lang_info->compiler, detected_compiler);
    } else {
        strcpy(lang_info->language, "C");
        strcpy(lang_info->compiler, "Clang");
    }

    free(symbols);
    free(string_table);
    fseek(file, current_offset, SEEK_SET);

    return 0;
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

                if (strcmp(segname, "__TEXT") == 0 && (strcmp(sectname, "__rodata") == 0 ||
                                                       strcmp(sectname, "__typelink") == 0 || strcmp(sectname, "__itablink") == 0)) {
                    strcpy(lang_info->language, "Go");
                    strcpy(lang_info->compiler, "gc (Go compiler)");
                    return 0;
                }

                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__gosymtab") == 0) {
                    strcpy(lang_info->language, "Go");
                    strcpy(lang_info->compiler, "gc (Go compiler)");
                    return 0;
                }

                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__rustc") == 0) {
                    strcpy(lang_info->language, "Rust");
                    strcpy(lang_info->compiler, "rustc");
                    return 0;
                }

                if (strcmp(segname, "__LLVM") == 0) {
                    if (strcmp(lang_info->language, "Unknown") == 0) {
                        strcpy(lang_info->compiler, "LLVM");
                    }
                }

                if (strcmp(segname, "__DATA") == 0 && strcmp(sectname, "__objc_data") == 0) {
                    strcpy(lang_info->language, "Objective-C");
                    strcpy(lang_info->compiler, "Clang");
                    return 0;
                }

                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__swift5_proto") == 0) {
                    strcpy(lang_info->language, "Swift");
                    strcpy(lang_info->compiler, "Apple Swift Compiler");
                    return 0;
                }

                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__kotlin") == 0) {
                    strcpy(lang_info->language, "Kotlin/Native");
                    strcpy(lang_info->compiler, "Kotlin Native Compiler");
                    return 0;
                }

                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__haskell_cr") == 0) {
                    strcpy(lang_info->language, "Haskell");
                    strcpy(lang_info->compiler, "GHC");
                    return 0;
                }

                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__erlang_atom_tab") == 0) {
                    strcpy(lang_info->language, "Erlang/Elixir");
                    strcpy(lang_info->compiler, "Erlang VM");
                    return 0;
                }

                if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__text") == 0 && mach_o_file->command_count <= 5) {
                    strcpy(lang_info->language, "Assembly");
                    strcpy(lang_info->compiler, "Assembler");
                    return 0;
                }
            }
        }

        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
    }

    return -1;
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

                    if (strstr(data, "Haskell") || strstr(data, "ghc")) {
                        strcpy(lang_info->language, "Haskell");
                        strcpy(lang_info->compiler, "GHC");
                        free(data);
                        fseek(file, current_offset, SEEK_SET);
                        return 0;
                    }

                    if (strstr(data, "Elixir") || strstr(data, "Erlang")) {
                        strcpy(lang_info->language, "Erlang/Elixir");
                        strcpy(lang_info->compiler, "Erlang VM");
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
