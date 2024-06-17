#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char* const argv[]) {
    if (argc != 2) {
        dprintf(STDERR_FILENO, "Usage: mkfifo NAME\n");
        return EXIT_FAILURE;
    }
    if (mkfifo(argv[1], 0) < 0) {
        perror("mkfifo");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
