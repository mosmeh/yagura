#include "stdlib.h"
#include "syscall.h"
#include <kernel/api/dirent.h>

int print_name(const struct dirent* dent) {
    switch (dent->type) {
    case DT_FIFO:
        return printf("\x1b[33m%s\x1b[m|", dent->name);
    case DT_DIR:
        return printf("\x1b[34m%s\x1b[m/", dent->name);
    case DT_LNK:
        return printf("\x1b[36m%s\x1b[m@", dent->name);
    case DT_SOCK:
        return printf("\x1b[35m%s\x1b[m=", dent->name);
    }
    return printf("%s", dent->name);
}

int main(int argc, char* argv[]) {
    const char* path;
    if (argc < 2) {
        static char path_buf[1024];
        getcwd(path_buf, 1024);
        path = path_buf;
    } else {
        path = argv[1];
    }

    DIR* dirp = opendir(path);
    if (!dirp) {
        perror("opendir");
        return EXIT_FAILURE;
    }

    size_t width = 0;
    for (;;) {
        struct dirent* dent = readdir(dirp);
        if (!dent)
            break;
        width += print_name(dent);
        if (width >= 50) { // arbitrary threshold
            putchar('\n');
            width = 0;
        } else {
            printf("\t");
        }
    }
    if (width > 0)
        putchar('\n');

    closedir(dirp);
    return EXIT_SUCCESS;
}
