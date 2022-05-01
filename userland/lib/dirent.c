#include "dirent.h"
#include "stdlib.h"
#include "sys/fcntl.h"
#include "unistd.h"

#define DIR_BUF_CAPACITY 1024

typedef struct DIR {
    int fd;
    unsigned char buf[DIR_BUF_CAPACITY];
    size_t buf_size;
    size_t buf_cursor;
} DIR;

DIR* opendir(const char* name) {
    DIR* dirp = malloc(sizeof(DIR));
    if (!dirp)
        return NULL;
    dirp->fd = open(name, O_RDONLY);
    if (dirp->fd < 0)
        return NULL;
    return dirp;
}

int closedir(DIR* dirp) {
    int rc = close(dirp->fd);
    free(dirp);
    return rc;
}

struct dirent* readdir(DIR* dirp) {
    if (dirp->buf_cursor >= dirp->buf_size) {
        ssize_t nwritten = getdents(dirp->fd, dirp->buf, DIR_BUF_CAPACITY);
        if (nwritten <= 0)
            return NULL;
        dirp->buf_size = nwritten;
        dirp->buf_cursor = 0;
    }
    struct dirent* dent = (struct dirent*)(dirp->buf + dirp->buf_cursor);
    dirp->buf_cursor += dent->d_reclen;
    return dent;
}
