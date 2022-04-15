#include "stdlib.h"
#include "syscall.h"

int main(int argc, char* const argv[]) {
    if (argc < 2) {
        dprintf(2, "Usage: mkdir DIRECTORY\n");
        return EXIT_FAILURE;
    }
    if (mkdir(argv[1], 0) < 0) {
        perror("mkdir");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
