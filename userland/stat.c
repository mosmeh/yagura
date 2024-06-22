#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static const char* file_type(struct stat* buf) {
    if (S_ISREG(buf->st_mode))
        return buf->st_size == 0 ? "regular empty file" : "regular file";
    if (S_ISDIR(buf->st_mode))
        return "directory";
    if (S_ISBLK(buf->st_mode))
        return "block special file";
    if (S_ISCHR(buf->st_mode))
        return "character special file";
    if (S_ISFIFO(buf->st_mode))
        return "fifo";
    if (S_ISLNK(buf->st_mode))
        return "symbolic link";
    if (S_ISSOCK(buf->st_mode))
        return "socket";
    return "weird file";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        dprintf(STDERR_FILENO, "Usage: stat FILE...\n");
        return EXIT_FAILURE;
    }
    for (int i = 1; i < argc; ++i) {
        const char* filename = argv[i];
        struct stat buf;
        if (stat(filename, &buf) < 0) {
            perror("stat");
            return EXIT_FAILURE;
        }
        printf("  File: %s\n"
               "  Size: %-10d\t%s\n"
               "Device: %d,%d\tLinks: %-5d",
               filename, buf.st_size, file_type(&buf), major(buf.st_dev),
               minor(buf.st_dev), buf.st_nlink);
        if (S_ISCHR(buf.st_mode) || S_ISBLK(buf.st_mode)) {
            printf("\tDevice type: %d,%d", major(buf.st_rdev),
                   minor(buf.st_rdev));
        }
        putchar('\n');
    }
    return EXIT_SUCCESS;
}
