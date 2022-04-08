#include "stdlib.h"
#include "syscall.h"
#include <kernel/api/dirent.h>

int main(int argc, char* argv[]) {
    const char* path = argc < 2 ? "/" : argv[1];
    DIR* dirp = opendir(path);
    if (!dirp) {
        perror("opendir");
        return EXIT_FAILURE;
    }
    struct dirent* dent;
    for (;;) {
        dent = readdir(dirp);
        if (!dent)
            break;
        puts(dent->name);
    }
    closedir(dirp);
    return EXIT_SUCCESS;
}
