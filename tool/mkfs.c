#include <common/initrd.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Too few args\n");
        return EXIT_FAILURE;
    }
    size_t num_files = argc - 2;

    puts("Creating initrd");

    FILE* out = fopen(argv[1], "wb");
    if (!out) {
        perror("fopen");
        return EXIT_FAILURE;
    }
    initrd_header header = {num_files};
    fwrite(&header, sizeof(initrd_header), 1, out);

    uint32_t offset =
        sizeof(initrd_header) + num_files * sizeof(initrd_file_header);
    uint32_t* lengths = malloc(num_files * sizeof(uint32_t));
    for (size_t i = 0; i < num_files; ++i) {
        char* filepath = argv[i + 2];
        printf("%s -> ", filepath);

        initrd_file_header file_header;
        file_header.offset = offset;
        strncpy(file_header.name, basename(filepath), 127);
        file_header.name[127] = '\0';
        puts(file_header.name);

        FILE* file = fopen(filepath, "rb");
        if (!file) {
            perror("fopen");
            fclose(out);
            free(lengths);
            return EXIT_FAILURE;
        }
        fseek(file, 0, SEEK_END);
        file_header.length = ftell(file);
        fclose(file);

        fwrite(&file_header, 1, sizeof(initrd_file_header), out);

        offset += file_header.length;
        lengths[i] = file_header.length;
    }

    for (size_t i = 0; i < num_files; ++i) {
        const char* filename = argv[i + 2];
        FILE* file = fopen(filename, "rb");

        uint8_t* buffer = (uint8_t*)malloc(lengths[i]);
        size_t nread = fread(buffer, sizeof(uint8_t), lengths[i], file);
        if (nread < lengths[i]) {
            perror("fread");
            fclose(out);
            free(lengths);
            free(buffer);
            fclose(file);
            return EXIT_FAILURE;
        }
        fwrite(buffer, sizeof(uint8_t), lengths[i], out);
        free(buffer);

        fclose(file);
    }

    fclose(out);
    free(lengths);

    return EXIT_SUCCESS;
}
