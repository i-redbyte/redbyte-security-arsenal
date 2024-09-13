#include <stdio.h>
#include <stdlib.h>
#include "../macho-analyzer/include/macho_analyzer.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Использование: %s <путь к Mach-O файлу>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *filename = argv[1];
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Ошибка при открытии файла");
        return EXIT_FAILURE;
    }

    MachOFile mach_o_file;
    if (analyze_mach_o(file, &mach_o_file) != 0) {
        fprintf(stderr, "Ошибка при анализе файла.\n");
        fclose(file);
        return EXIT_FAILURE;
    }

    // Выводим информацию на экран
    print_mach_o_info(&mach_o_file);

    // Освобождаем ресурсы
    free_mach_o_file(&mach_o_file);
    fclose(file);

    return EXIT_SUCCESS;
}
