#include <stdio.h>
#include <stdlib.h>
#include <sys/limits.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        dprintf(STDERR_FILENO, "Usage: FILE...\n");
        return EXIT_FAILURE;
    }

    char target[SYMLINK_MAX + 1] = {0};
    for (int i = 1; i < argc; i++) {
        if (readlink(argv[i], target, SYMLINK_MAX) < 0) {
            perror("readlink");
            return EXIT_FAILURE;
        }
        puts(target);
    }

    return EXIT_SUCCESS;
}
