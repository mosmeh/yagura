#include "stdlib.h"
#include "syscall.h"
#include <kernel/api/fcntl.h>

#define BUF_SIZE 1024
char buf[BUF_SIZE];

int main(int argc, char* argv[]) {
    if (argc < 2) {
        dprintf(2, "Usage: cat filename\n");
        return EXIT_FAILURE;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }
    for (;;) {
        ssize_t nread = read(fd, buf, BUF_SIZE - 1);
        if (nread < 0) {
            perror("read");
            close(fd);
            return EXIT_FAILURE;
        }
        if (nread == 0)
            break;
        buf[nread] = '\0';
        puts(buf);
        if (nread < BUF_SIZE - 1)
            break;
    }
    close(fd);

    return EXIT_SUCCESS;
}
