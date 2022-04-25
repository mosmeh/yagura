#include "stdlib.h"
#include "syscall.h"
#include <kernel/api/unistd.h>

int main(int argc, char* const argv[]) {
    if (argc < 2) {
        dprintf(STDERR_FILENO, "Usage: mkdir DIRECTORY\n");
        return EXIT_FAILURE;
    }
    if (mkdir(argv[1], 0) < 0) {
        perror("mkdir");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
