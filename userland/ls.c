#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/limits.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static const char* get_format(const char* name, mode_t mode, size_t* out_len) {
    switch (mode & S_IFMT) {
    case S_IFDIR:
        *out_len = strlen(name) + 1;
        return "\x1b[01;34m%s\x1b[m/";
    case S_IFCHR:
    case S_IFBLK:
        *out_len = strlen(name);
        return "\x1b[01;33m%s\x1b[m";
    case S_IFIFO:
        *out_len = strlen(name) + 1;
        return "\x1b[33m%s\x1b[m|";
    case S_IFLNK:
        *out_len = strlen(name) + 1;
        return "\x1b[01;36m%s\x1b[m@";
    case S_IFSOCK:
        *out_len = strlen(name) + 1;
        return "\x1b[01;35m%s\x1b[m=";
    case S_IFREG:
    default:
        if (mode & S_IXUSR) {
            *out_len = strlen(name) + 1;
            return "\x1b[01;32m%s\x1b[m*";
        } else {
            *out_len = strlen(name);
            return "%s";
        }
    }
}

static char get_file_type_char(mode_t mode) {
    switch (mode & S_IFMT) {
    case S_IFDIR:
        return 'd';
    case S_IFCHR:
        return 'c';
    case S_IFBLK:
        return 'b';
    case S_IFIFO:
        return 'p';
    case S_IFLNK:
        return 'l';
    case S_IFSOCK:
        return 's';
    case S_IFREG:
    default:
        return '-';
    }
}

#define TAB_STOP 8

static int list_dir(const char* path, size_t terminal_width, bool long_format) {
    int ret = -1;
    DIR* dirp = NULL;
    char* full_path = NULL;

    dirp = opendir(path);
    if (!dirp) {
        perror("opendir");
        goto fail;
    }

    size_t path_len = strlen(path);
    size_t x_pos = 0;
    for (;;) {
        errno = 0;
        struct dirent* dent = readdir(dirp);
        if (!dent) {
            if (errno == 0)
                break;
            perror("readdir");
            goto fail;
        }

        size_t name_len = strlen(dent->d_name);
        full_path = malloc(path_len + 1 + name_len + 1);
        if (!full_path) {
            perror("malloc");
            goto fail;
        }
        strcpy(full_path, path);
        full_path[path_len] = '/';
        strcpy(full_path + path_len + 1, dent->d_name);

        struct stat st;
        ret = lstat(full_path, &st);
        if (ret < 0) {
            perror("lstat");
            goto fail;
        }

        size_t len;
        const char* format = get_format(dent->d_name, st.st_mode, &len);
        if (long_format) {
            printf("%c %3u ", get_file_type_char(st.st_mode), st.st_nlink);
            if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
                printf(" %4u,%4u ", major(st.st_rdev), minor(st.st_rdev));
            else
                printf("%10u ", st.st_size);

            printf(format, dent->d_name);
            if (S_ISLNK(st.st_mode)) {
                char target[SYMLINK_MAX + 1] = {0};
                if (readlink(full_path, target, SYMLINK_MAX) < 0) {
                    perror("readlink");
                    goto fail;
                }
                printf(" -> %s", target);
            }

            putchar('\n');
        } else {
            size_t next_pos = round_up(x_pos + len + 1, TAB_STOP);
            if (next_pos >= terminal_width) {
                x_pos = round_up(len + 1, TAB_STOP);
                putchar('\n');
            } else {
                x_pos = next_pos;
            }
            printf(format, dent->d_name);
            putchar('\t');
        }

        free(full_path);
        full_path = NULL;
    }
    if (x_pos > 0)
        putchar('\n');

    ret = 0;
fail:
    putchar('\n');
    free(full_path);
    if (dirp)
        closedir(dirp);
    return ret;
}

int main(int argc, char* argv[]) {
    bool long_format = false;
    size_t num_dirs = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-l"))
            long_format = true;
        else
            ++num_dirs;
    }

    size_t terminal_width = 80;
    struct winsize winsize;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) >= 0)
        terminal_width = winsize.ws_col;

    if (num_dirs == 0) {
        static char path_buf[PATH_MAX];
        getcwd(path_buf, PATH_MAX);
        if (list_dir(path_buf, terminal_width, long_format) < 0)
            return EXIT_FAILURE;
        return EXIT_SUCCESS;
    }

    int ret = EXIT_SUCCESS;
    for (int i = 1; i < argc; i++) {
        const char* arg = argv[i];
        if (!strcmp(arg, "-l"))
            continue;
        if (num_dirs > 1)
            printf("%s:\n", arg);
        if (list_dir(arg, terminal_width, long_format) < 0)
            ret = EXIT_FAILURE;
    }
    return ret;
}
