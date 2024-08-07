#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUF_SIZE 1024

static int process_file(const char* name, const char* filename) {
    int fd = strcmp(filename, "-") ? open(filename, O_RDONLY) : STDIN_FILENO;
    if (fd < 0) {
        perror("open");
        return -1;
    }

    size_t lines = 0;
    size_t words = 0;
    size_t bytes = 0;
    bool in_word = false;
    for (;;) {
        static char buf[BUF_SIZE];
        ssize_t nread = read(fd, buf, BUF_SIZE);
        if (nread < 0) {
            perror("read");
            if (fd != STDIN_FILENO)
                close(fd);
            return -1;
        }
        if (nread == 0)
            break;
        for (ssize_t i = 0; i < nread; ++i) {
            ++bytes;
            if (buf[i] == '\n')
                ++lines;
            if (isspace(buf[i])) {
                in_word = false;
            } else if (!in_word) {
                ++words;
                in_word = true;
            }
        }
    }

    printf("%7u %7u %7u %s\n", lines, words, bytes, name);

    if (fd != STDIN_FILENO)
        close(fd);
    return 0;
}

int main(int argc, char* argv[]) {
    int ret = EXIT_SUCCESS;
    if (argc < 2) {
        if (process_file("", "-") < 0)
            ret = EXIT_FAILURE;
    }
    for (int i = 1; i < argc; ++i) {
        if (process_file(argv[i], argv[i]) < 0)
            ret = EXIT_FAILURE;
    }
    return ret;
}
