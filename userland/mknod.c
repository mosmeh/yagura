#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static noreturn void usage(void) {
    dprintf(STDERR_FILENO, "Usage: mknod NAME TYPE [MAJOR MINOR]\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char* const argv[]) {
    if (argc < 3 || argc > 5)
        usage();

    const char* filename = argv[1];
    const char* type_str = argv[2];
    if (!type_str[0] || type_str[1])
        usage();

    char type = type_str[0];
    mode_t mode;
    dev_t dev = 0;

    switch (type) {
    case 'b':
    case 'c':
    case 'u': {
        if (argc != 5)
            usage();
        if (!str_is_uint(argv[3]) || !str_is_uint(argv[4]))
            usage();
        mode = type == 'b' ? S_IFBLK : S_IFCHR;
        int major = atoi(argv[3]);
        int minor = atoi(argv[4]);
        dev = makedev(major, minor);
        break;
    }
    case 'p':
        if (argc != 3)
            usage();
        mode = S_IFIFO;
        break;
    default:
        usage();
    }

    if (mknod(filename, mode, dev) < 0) {
        perror("mknod");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
