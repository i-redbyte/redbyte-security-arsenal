#include "lc_commands.h"
#include "hash_table.h"

/**
 * Массив с информацией обо всех поддерживаемых LC командах.
 */
static const LCCommandInfo lc_commands[] = {
        {"LC_SEGMENT", "Specifies a segment of the Mach-O file.", "Указывает сегмент файла Mach-O."},
        {"LC_SEGMENT_64", "Specifies a 64-bit segment of the Mach-O file.", "Указывает 64-битный сегмент файла Mach-O."},
        {"LC_SYMTAB", "Specifies the symbol table information.", "Указывает информацию о таблице символов."},
        {"LC_DYSYMTAB", "Specifies the dynamic symbol table information.", "Указывает информацию о динамической таблице символов."},
        {"LC_LOAD_DYLIB", "Loads a dynamic library (dylib).", "Загружает динамическую библиотеку (dylib)."},
        {"LC_LOAD_WEAK_DYLIB", "Loads a weak dynamic library (dylib).", "Загружает слабую динамическую библиотеку (dylib)."},
        {"LC_REEXPORT_DYLIB", "Specifies a re-exported dynamic library.", "Указывает реэкспортируемую динамическую библиотеку."},
        {"LC_LOAD_UPWARD_DYLIB", "Loads an upward dynamic library.", "Загружает динамическую библиотеку вверх по иерархии."},
        {"LC_LOAD_DYLINKER", "Specifies the dynamic linker to be used.", "Указывает динамический компоновщик для использования."},
        {"LC_UUID", "Specifies the unique identifier (UUID) for the Mach-O file.", "Указывает уникальный идентификатор (UUID) для файла Mach-O."},
        {"LC_VERSION_MIN_MACOSX", "Specifies the minimum macOS version required.", "Указывает минимальную версию macOS, необходимую для работы."},
        {"LC_VERSION_MIN_IPHONEOS", "Specifies the minimum iPhoneOS version required.", "Указывает минимальную версию iPhoneOS, необходимую для работы."},
        {"LC_SOURCE_VERSION", "Specifies the source version of the binary.", "Указывает версию исходного кода бинарного файла."},
        {"LC_MAIN", "Specifies the main entry point of the Mach-O file.", "Указывает основную точку входа файла Mach-O."},
        {"LC_FUNCTION_STARTS", "Specifies the offset to function start addresses.", "Указывает смещение до адресов начала функций."},
        {"LC_DATA_IN_CODE", "Specifies data regions embedded in code sections.", "Указывает регионы данных, встроенные в секции кода."},
        {"LC_CODE_SIGNATURE", "Specifies the code signature of the binary.", "Указывает подпись кода бинарного файла."},
        {"LC_ENCRYPTION_INFO", "Specifies encryption information for the Mach-O file.", "Указывает информацию о шифровании файла Mach-O."},
        {"LC_ENCRYPTION_INFO_64", "Specifies 64-bit encryption information for the Mach-O file.", "Указывает 64-битную информацию о шифровании файла Mach-O."},
        {"LC_RPATH", "Specifies the runtime search path for dynamic libraries.", "Указывает путь поиска динамических библиотек во время выполнения."},
        {"LC_BUILD_VERSION", "Specifies the build version of the Mach-O file.", "Указывает версию сборки файла Mach-O."},
        {"LC_LINKER_OPTION", "Specifies linker options for the binary.", "Указывает опции компоновщика для бинарного файла."},
        {"LC_NOTE", "Specifies arbitrary notes associated with the Mach-O file.", "Указывает произвольные заметки, связанные с файлом Mach-O."},
        {"LC_PREBOUND_DYLIB", "Indicates a prebound dynamic library.", "Указывает предварительно связанную динамическую библиотеку."},
        {"LC_ID_DYLIB", "Specifies the ID of the dynamic library.", "Указывает идентификатор динамической библиотеки."},
        {"LC_ID_DYLINKER", "Specifies the ID of the dynamic linker.", "Указывает идентификатор динамического компоновщика."},
        {"LC_PREPAGE", "Specifies pre-paging of the executable.", "Указывает предварительную загрузку исполняемого файла в память."},
        {"LC_ROUTINES", "Specifies routine information for the binary.", "Указывает информацию о процедурах для бинарного файла."},
        {"LC_ROUTINES_64", "Specifies 64-bit routine information for the binary.", "Указывает 64-битную информацию о процедурах для бинарного файла."},
        {"LC_SUB_CLIENT", "Specifies a sub-client of the Mach-O file.", "Указывает под-клиента файла Mach-O."},
        {"LC_SUB_FRAMEWORK", "Specifies a sub-framework for the Mach-O file.", "Указывает под-фреймворк файла Mach-O."},
        {"LC_SUB_LIBRARY", "Specifies a sub-library for the Mach-O file.", "Указывает под-библиотеку файла Mach-O."},
        {"LC_TWOLEVEL_HINTS", "Specifies two-level namespace hints for dynamic libraries.", "Указывает подсказки для двухуровневого пространства имен динамических библиотек."},
        {"LC_DYLD_ENVIRONMENT", "Specifies environment variables for the dynamic linker.", "Указывает переменные окружения для динамического компоновщика."},
        {"LC_THREAD", "Specifies thread state information for the binary.", "Указывает информацию о состоянии потока для бинарного файла."},
        {"LC_UNIXTHREAD", "Specifies UNIX thread state information.", "Указывает информацию о состоянии потока в UNIX."}
};



static const size_t lc_commands_count = sizeof(lc_commands) / sizeof(LCCommandInfo);
static HashTable *lc_command_table = NULL;

void initialize_lc_command_table() {
    lc_command_table = hash_table_create();
    if (!lc_command_table) {
        fprintf(stderr, "Error initializing LC command hash table.\n");
        return;
    }

    for (size_t i = 0; i < lc_commands_count; ++i) {
        hash_table_insert(lc_command_table, lc_commands[i].name, (void *)&lc_commands[i]);
    }
}

void destroy_lc_command_table() {
    if (lc_command_table) {
        hash_table_destroy(lc_command_table, NULL);
        lc_command_table = NULL;
    }
}

const LCCommandInfo* get_lc_command_info(const char *name) {
    if (!lc_command_table) {
        initialize_lc_command_table();
    }
    return (const LCCommandInfo *)hash_table_get(lc_command_table, name);
}

void print_lc_command_info(const LCCommandInfo *info, Language lang) {
    if (!info) return;

    printf("Command: %s\n", info->name);
    switch (lang) {
        case LANG_RU:
            printf("Description: %s\n", info->description_ru);
            break;
        case LANG_EN:
        default:
            printf("Description: %s\n", info->description_en);
            break;
    }
}

void print_all_lc_commands(Language lang) {
    for (size_t i = 0; i < lc_commands_count; ++i) {
        print_lc_command_info(&lc_commands[i], lang);
        printf("\n");
    }
}