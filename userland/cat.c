#include "io.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUF_SIZE 1024

static int dump_file(const char* filename) {
    int fd = strcmp(filename, "-") ? open(filename, O_RDONLY) : STDIN_FILENO;
    if (fd < 0) {
        perror("open");
        return -1;
    }
    int ret = -1;
    for (;;) {
        static char buf[BUF_SIZE];
        ssize_t nread = read(fd, buf, BUF_SIZE);
        if (nread < 0) {
            perror("read");
            goto fail;
        }
        if (nread == 0)
            break;
        if (write_all(STDOUT_FILENO, buf, nread) < 0) {
            perror("write");
            goto fail;
        }
    }
    ret = 0;
fail:
    if (fd != STDIN_FILENO)
        close(fd);
    return ret;
}

int main(int argc, char* argv[]) {
    int ret = EXIT_SUCCESS;
    if (argc < 2) {
        if (dump_file("-") < 0)
            ret = EXIT_FAILURE;
    }
    for (int i = 1; i < argc; ++i) {
        if (dump_file(argv[i]) < 0)
            ret = EXIT_FAILURE;
    }
    return ret;
}
