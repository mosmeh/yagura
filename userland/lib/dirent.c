#include "dirent.h"
#include "errno.h"
#include "fcntl.h"
#include "private.h"
#include "stdlib.h"
#include "unistd.h"
#include <common/extra.h>
#include <common/string.h>

static long getdents(int fd, struct linux_dirent* dirp, size_t count) {
    RETURN_WITH_ERRNO(long, SYSCALL3(getdents, fd, dirp, count));
}

typedef struct __DIR {
    int fd;
    struct linux_dirent* buf;
    size_t buf_capacity, buf_size;
    size_t buf_cursor;
    struct dirent dent;
} DIR;

DIR* opendir(const char* name) {
    DIR* dirp = malloc(sizeof(DIR));
    if (!dirp)
        return NULL;
    *dirp = (DIR){0};
    dirp->fd = open(name, O_RDONLY);
    if (dirp->fd < 0) {
        free(dirp);
        return NULL;
    }
    dirp->buf_capacity = 1024;
    return dirp;
}

int closedir(DIR* dirp) {
    int rc = close(dirp->fd);
    free(dirp->buf);
    free(dirp);
    return rc;
}

struct dirent* readdir(DIR* dirp) {
    if (dirp->buf_cursor >= dirp->buf_size) {
        int saved_errno = errno;
        for (;;) {
            struct linux_dirent* new_buf =
                realloc(dirp->buf, dirp->buf_capacity);
            if (!new_buf)
                return NULL;
            dirp->buf = new_buf;
            errno = 0;
            ssize_t nread = getdents(dirp->fd, dirp->buf, dirp->buf_capacity);
            if (nread == 0) {
                errno = saved_errno;
                return NULL;
            }
            if (nread > 0) {
                dirp->buf_size = nread;
                break;
            }
            if (errno != EINVAL)
                return NULL;
            dirp->buf_capacity *= 2;
        }
        errno = saved_errno;
        dirp->buf_cursor = 0;
    }

    const struct linux_dirent* src =
        (struct linux_dirent*)((unsigned char*)dirp->buf + dirp->buf_cursor);
    struct dirent* dest = &dirp->dent;
    dest->d_ino = src->d_ino;
    dest->d_off = src->d_off;
    dest->d_reclen = sizeof(struct dirent);
    size_t name_size =
        src->d_reclen - 2 - offsetof(struct linux_dirent, d_name);
    name_size = MIN(name_size, sizeof(dest->d_name));
    strlcpy(dest->d_name, src->d_name, name_size);
    dest->d_type = *(src->d_name + name_size + 2);
    dirp->buf_cursor += src->d_reclen;
    return dest;
}
