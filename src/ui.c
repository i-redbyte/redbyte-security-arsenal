#include "../include/ui.h"
#include <ncurses.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <macho_analyzer.h>
#include <language_detector.h>

void ui_init() {
    initscr();              // Инициализация экрана
    cbreak();               // Отключение буферизации ввода
    noecho();               // Отключение вывода вводимых символов
    keypad(stdscr, TRUE);   // Включение обработки функциональных клавиш
    curs_set(0);            // Скрыть курсор

    // Инициализация цветов, если поддерживается
    if (has_colors()) {
        start_color();
        init_pair(1, COLOR_WHITE, COLOR_BLUE);
    }
}

void ui_end() {
    endwin();
}

const char* ui_select_file() {
    DIR *dir;
    struct dirent *entry;
    int highlight = 0;
    int choice = 0;
    int n_files = 0;
    const int max_files = 100;
    char *files[max_files];

    dir = opendir(".");
    if (!dir) {
        perror("opendir");
        return NULL;
    }

    while ((entry = readdir(dir)) != NULL && n_files < max_files) {
        if (entry->d_type == DT_REG) {  // Только файлы
            files[n_files] = strdup(entry->d_name);
            n_files++;
        }
    }
    closedir(dir);

    if (n_files == 0) {
        clear();
        mvprintw(0, 0, "Нет доступных файлов.");
        refresh();
        getch();
        return NULL;
    }

    while (1) {
        clear();
        mvprintw(0, 0, "Выберите файл Mach-O:");
        for (int i = 0; i < n_files; i++) {
            if (i == highlight) {
                attron(A_REVERSE);
            }
            mvprintw(i + 1, 0, files[i]);
            attroff(A_REVERSE);
        }

        int c = getch();
        switch (c) {
            case KEY_UP:
                if (highlight > 0) {
                    highlight--;
                }
                break;
            case KEY_DOWN:
                if (highlight < n_files - 1) {
                    highlight++;
                }
                break;
            case 10:  // Enter
                choice = highlight;
                goto end;
        }
    }

    end:
    for (int i = 0; i < n_files; i++) {
        if (i != choice) {
            free(files[i]);
        }
    }

    return files[choice];  // Возвращаем выбранный файл
}

void ui_display_mach_o_info(MachOFile *mach_o_file, FILE *file) {
    clear();
    mvprintw(0, 0, "Mach-O File Information (Use UP/DOWN keys to scroll, 'q' to quit)");

    int total_rows = 0;
    int max_rows, max_cols;
    getmaxyx(stdscr, max_rows, max_cols);

    // Собираем информацию в массив строк
#define MAX_INFO_LINES 100
    char *info_lines[MAX_INFO_LINES];
    int info_count = 0;

    info_lines[info_count++] = strdup("Header Information:");
    char buffer[256];

    snprintf(buffer, sizeof(buffer), "  Magic: 0x%X", mach_o_file->header.header64.magic);
    info_lines[info_count++] = strdup(buffer);

    snprintf(buffer, sizeof(buffer), "  CPU Type: %d", mach_o_file->header.header64.cputype);
    info_lines[info_count++] = strdup(buffer);

    snprintf(buffer, sizeof(buffer), "  CPU Subtype: %d", mach_o_file->header.header64.cpusubtype);
    info_lines[info_count++] = strdup(buffer);

    snprintf(buffer, sizeof(buffer), "  File Type: %d", mach_o_file->header.header64.filetype);
    info_lines[info_count++] = strdup(buffer);

    snprintf(buffer, sizeof(buffer), "  Number of Commands: %d", mach_o_file->header.header64.ncmds);
    info_lines[info_count++] = strdup(buffer);

    snprintf(buffer, sizeof(buffer), "  Size of Commands: %d", mach_o_file->header.header64.sizeofcmds);
    info_lines[info_count++] = strdup(buffer);

    snprintf(buffer, sizeof(buffer), "  Flags: 0x%X", mach_o_file->header.header64.flags);
    info_lines[info_count++] = strdup(buffer);

    info_lines[info_count++] = strdup("Load Commands:");

    if (mach_o_file->commands) {
        for (uint32_t i = 0; i < mach_o_file->header.header64.ncmds; i++) {
            snprintf(buffer, sizeof(buffer), "  Command %d: 0x%X", i + 1, mach_o_file->commands[i].cmd);
            info_lines[info_count++] = strdup(buffer);
        }
    } else {
        info_lines[info_count++] = strdup("  No Load Commands found.");
    }

    // Отображение с возможностью прокрутки
    int current_line = 0;
    int ch;

    while (1) {
        clear();
        mvprintw(0, 0, "Mach-O File Information (Use UP/DOWN keys to scroll, 'q' to quit)");

        for (int i = 0; i < max_rows - 2 && (current_line + i) < info_count; i++) {
            mvprintw(i + 1, 0, "%s", info_lines[current_line + i]);
        }

        refresh();
        ch = getch();
        if (ch == KEY_UP) {
            if (current_line > 0) {
                current_line--;
            }
        } else if (ch == KEY_DOWN) {
            if ((current_line + max_rows - 2) < info_count) {
                current_line++;
            }
        } else if (ch == 'q' || ch == 'Q') {
            break;
        }
    }

    // Освобождаем память
    for (int i = 0; i < info_count; i++) {
        free(info_lines[i]);
    }
}

void ui_display_dynamic_libraries(MachOFile *mach_o_file) {
    clear();
    mvprintw(0, 0, "List of Dynamic Libraries (Use UP/DOWN keys to scroll, 'q' to quit)");

    int max_rows, max_cols;
    getmaxyx(stdscr, max_rows, max_cols);

    // Собираем имена динамических библиотек в массив
    char **dylib_names = NULL;
    uint32_t num_dylibs = 0;

    for (uint32_t i = 0; i < mach_o_file->command_count; i++) {
        struct load_command *lc = &(mach_o_file->commands[i]);

        if (lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB) {
            struct dylib_command *dylib_cmd = (struct dylib_command *)lc;
            uint32_t name_offset = dylib_cmd->dylib.name.offset;
            char *dylib_name;

            if (mach_o_file->is_64_bit) {
                dylib_name = (char *)lc + name_offset;
            } else {
                dylib_name = (char *)lc + name_offset;
            }

            // Добавляем имя библиотеки в массив
            num_dylibs++;
            dylib_names = realloc(dylib_names, num_dylibs * sizeof(char *));
            if (!dylib_names) {
                // Обработка ошибки выделения памяти
                ui_display_error("Memory allocation error.");
                return;
            }
            dylib_names[num_dylibs - 1] = strdup(dylib_name);
        }
    }

    if (num_dylibs == 0) {
        mvprintw(2, 0, "No dynamic libraries found.");
        refresh();
        getch();
        return;
    }

    // Отображаем динамические библиотеки с возможностью прокрутки
    int current_line = 0;
    int ch;

    while (1) {
        clear();
        mvprintw(0, 0, "List of Dynamic Libraries (Use UP/DOWN keys to scroll, 'q' to quit)");

        for (int i = 0; i < max_rows - 2 && (current_line + i) < num_dylibs; i++) {
            mvprintw(i + 1, 0, "%s", dylib_names[current_line + i]);
        }

        refresh();
        ch = getch();
        if (ch == KEY_UP) {
            if (current_line > 0) {
                current_line--;
            }
        } else if (ch == KEY_DOWN) {
            if ((current_line + max_rows - 2) < num_dylibs) {
                current_line++;
            }
        } else if (ch == 'q' || ch == 'Q') {
            break;
        }
    }

    // Освобождаем выделенную память
    for (uint32_t i = 0; i < num_dylibs; i++) {
        free(dylib_names[i]);
    }
    free(dylib_names);
}


void ui_display_language_info(LanguageInfo *lang_info) {
    clear();
    mvprintw(0, 0, "Language and Compiler Information");
    mvprintw(2, 0, "Language: %s", lang_info->language);
    mvprintw(3, 0, "Compiler: %s", lang_info->compiler);
    refresh();
    getch();
}

void ui_display_error(const char *message) {
    clear();
    mvprintw(0, 0, "Error: %s", message);
    refresh();
    getch();
}
