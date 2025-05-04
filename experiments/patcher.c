#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TARGET_STRING "hello, world\n"
#define REPEAT_COUNT 10

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <target_binary>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    FILE *f = fopen(filename, "r+b");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    unsigned char *data = malloc(size);
    fread(data, 1, size, f);

    unsigned char *pos = (unsigned char *)memmem(data, size, TARGET_STRING, strlen(TARGET_STRING));
    if (!pos) {
        fprintf(stderr, "Target string not found in binary\n");
        free(data);
        fclose(f);
        return 1;
    }

    long offset = pos - data;

    char repeated[sizeof(TARGET_STRING) * REPEAT_COUNT] = {0};
    for (int i = 0; i < REPEAT_COUNT; i++) {
        strcat(repeated, TARGET_STRING);
    }

    fseek(f, offset, SEEK_SET);
    fwrite(repeated, 1, strlen(repeated), f);

    printf("Binary patched at offset 0x%lx\n", offset);

    free(data);
    fclose(f);
    return 0;
}
