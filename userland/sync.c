#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        sync();
        return EXIT_SUCCESS;
    }
    for (int i = 1; i < argc; ++i) {
        int fd = open(argv[i], O_RDONLY);
        if (fd < 0) {
            perror("open");
            return EXIT_FAILURE;
        }
        int result = fsync(fd);
        if (result < 0) {
            perror("fsync");
            close(fd);
            return EXIT_FAILURE;
        }
        close(fd);
    }
    return EXIT_SUCCESS;
}
