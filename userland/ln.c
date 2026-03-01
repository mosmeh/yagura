#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(void) {
    dprintf(STDERR_FILENO, "Usage: ln TARGET LINK_NAME\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char* argv[]) {
    if (argc < 3)
        usage();

    const char* target = NULL;
    const char* link_name = NULL;
    bool symbolic = false;
    for (int i = 1; i < argc; i++) {
        const char* arg = argv[i];
        if (!strcmp(arg, "-s"))
            symbolic = true;
        else if (!target)
            target = arg;
        else if (!link_name)
            link_name = arg;
        else
            usage();
    }

    if (symbolic) {
        if (symlink(target, link_name) < 0) {
            perror("symlink");
            return EXIT_FAILURE;
        }
    } else if (link(target, link_name) < 0) {
        perror("link");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
