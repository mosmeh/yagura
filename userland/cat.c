#include "stdlib.h"
#include "syscall.h"
#include <kernel/api/fcntl.h>

#define BUF_SIZE 1024

static int dump_file(const char* filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        return -1;
    for (;;) {
        static char buf[BUF_SIZE];
        ssize_t nread = read(fd, buf, BUF_SIZE - 1);
        if (nread < 0) {
            close(fd);
            return -1;
        }
        if (nread == 0)
            break;
        buf[nread] = '\0';
        puts(buf);
        if (nread < BUF_SIZE - 1)
            break;
    }
    close(fd);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        dprintf(2, "Usage: cat FILE...\n");
        return EXIT_FAILURE;
    }
    for (int i = 1; i < argc; ++i) {
        if (dump_file(argv[i])) {
            perror("dump_file");
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
