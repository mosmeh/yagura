#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

static void usage(void) {
    dprintf(STDERR_FILENO, "Usage: mount [-t fstype] SOURCE TARGET\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char* argv[]) {
    if (argc < 3)
        usage();

    size_t num_positionals = 0;
    const char* source = NULL;
    const char* target = NULL;
    const char* fs_type = NULL;
    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        if (arg[0] != '-') {
            switch (num_positionals++) {
            case 0:
                source = arg;
                break;
            case 1:
                target = arg;
                break;
            default:
                usage();
            }
            continue;
        }
        if (!strcmp(arg, "-t")) {
            fs_type = argv[++i];
            continue;
        }
        usage();
    }
    if (!source || !target)
        usage();
    if (!fs_type) {
        dprintf(STDERR_FILENO, "you must specify the filesystem type\n");
        return EXIT_FAILURE;
    }

    if (mount(source, target, fs_type, 0, NULL) < 0) {
        perror("mount");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
