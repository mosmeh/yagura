#include "stdlib.h"
#include "syscall.h"
#include <common/stdlib.h>

int main(int argc, char* const argv[]) {
    if (argc < 2) {
        dprintf(2, "Usage: sleep NUMBER\n");
        return EXIT_FAILURE;
    }
    struct timespec req = {.tv_sec = atoi(argv[1]), .tv_nsec = 0};
    if (nanosleep(&req, NULL) < 0) {
        perror("nanosleep");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}