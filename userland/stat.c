#include "fs.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/limits.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static const char* file_type(const struct stat* buf) {
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
        if (lstat(filename, &buf) < 0) {
            perror("lstat");
            return EXIT_FAILURE;
        }

        printf("  File: %s", filename);

        if (S_ISLNK(buf.st_mode)) {
            char target[SYMLINK_MAX + 1] = {0};
            if (readlink(filename, target, SYMLINK_MAX) < 0) {
                perror("readlink");
                return EXIT_FAILURE;
            }
            printf(" -> %s\n", target);
        } else {
            putchar('\n');
        }

        printf("  Size: %-10ld\tBlocks: %-10llu IO Block: %-6ld %s\n"
               "Device: %xh/%ud\tInode: %-10lu  Links: %-5u",
               buf.st_size, (unsigned long long)buf.st_blocks, buf.st_blksize,
               file_type(&buf), buf.st_dev, buf.st_dev, buf.st_ino,
               buf.st_nlink);
        if (S_ISCHR(buf.st_mode) || S_ISBLK(buf.st_mode)) {
            printf("\tDevice type: %x,%x\n", major(buf.st_rdev),
                   minor(buf.st_rdev));
        } else {
            putchar('\n');
        }

        char mode_str[11];
        mode_to_string(buf.st_mode, mode_str);
        printf("Access: (%04o/%s)  Uid: (%5u)   Gid: (%5u)\n",
               buf.st_mode & ALLPERMS, mode_str, buf.st_uid, buf.st_gid);
    }
    return EXIT_SUCCESS;
}
