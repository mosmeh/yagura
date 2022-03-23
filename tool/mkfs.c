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
    FILE* out = fopen(argv[1], "wb");
    if (!out) {
        fprintf(stderr, "Could not open file \"initrd\"\n");
        return EXIT_FAILURE;
    }
    fwrite(&num_files, sizeof(uint32_t), 1, out);

    uint32_t offset = 0;
    uint32_t* lengths = malloc(num_files * sizeof(uint32_t));
    for (size_t i = 0; i < num_files; ++i) {
        char* filepath = argv[i + 2];
        printf("Scanning %s...\n", filepath);

        FILE* file = fopen(filepath, "rb");
        if (!file) {
            fprintf(stderr, "Could not open file\n");
            return EXIT_FAILURE;
        }

        initrd_file_header header;
        strncpy(header.name, basename(filepath), 127);
        header.name[127] = '\0';
        header.offset = offset;

        fseek(file, 0, SEEK_END);
        header.length = ftell(file);

        fclose(file);

        fwrite(&header, 1, sizeof(initrd_file_header), out);

        offset += header.length;
        lengths[i] = header.length;
    }

    for (size_t i = 0; i < num_files; ++i) {
        const char* filename = argv[i + 2];
        printf("Reading %s...\n", filename);

        FILE* file = fopen(filename, "rb");
        if (!file) {
            fprintf(stderr, "Could not open file\n");
            return EXIT_FAILURE;
        }

        uint8_t* buffer = (uint8_t*)malloc(lengths[i]);
        size_t nread = fread(buffer, sizeof(uint8_t), lengths[i], file);
        if (nread < lengths[i]) {
            fprintf(stderr, "Failed to read file\n");
            return EXIT_FAILURE;
        }
        fwrite(buffer, sizeof(uint8_t), lengths[i], out);
        free(buffer);

        fclose(file);
    }

    fclose(out);
    free(lengths);
    printf("Wrote to %s\n", argv[1]);

    return EXIT_SUCCESS;
}
