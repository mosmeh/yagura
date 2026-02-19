#include "io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char* const argv[]) {
    if (argc < 2) {
        putchar('\n');
        return EXIT_SUCCESS;
    }

    size_t total_size = 0;
    for (int i = 1; i < argc; ++i)
        total_size += strlen(argv[i]);

    size_t buf_size = sizeof(char) * (total_size + argc - 1);
    char* buf = malloc(buf_size);
    if (!buf) {
        perror("malloc");
        return EXIT_FAILURE;
    }

    char* p = buf;
    for (int i = 1; i < argc; ++i) {
        size_t len = strlen(argv[i]);
        memcpy(p, argv[i], len);
        p += len;
        *p++ = (i == argc - 1) ? '\n' : ' ';
    }

    ssize_t nwritten = write_all(STDOUT_FILENO, buf, buf_size);
    free(buf);
    if (nwritten < 0) {
        perror("write");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
