#include <kernel/api/fcntl.h>
#include <kernel/api/sys/uio.h>
#include <kernel/fs/file.h>
#include <kernel/fs/vfs.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>

// To avoid undefined behavior when shifting by LONG_WIDTH,
// shift by HALF_LONG_WIDTH twice.
#define HALF_LONG_WIDTH (LONG_WIDTH / 2)

NODISCARD static ssize_t pread(struct file* file, void* user_buf, size_t count,
                               uint64_t offset) {
    if (count == 0)
        return 0;
    if (!is_user_range(user_buf, count))
        return -EFAULT;
    ssize_t nread = file_read(file, user_buf, count, offset);
    if (nread == -EINTR)
        return -ERESTARTSYS;
    return nread;
}

SYSCALL3(read, int, fd, void*, user_buf, size_t, count) {
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);
    SCOPED_LOCK(file, file);
    ssize_t nread = pread(file, user_buf, count, file->offset);
    if (IS_OK(nread))
        file->offset += nread;
    return nread;
}

SYSCALL4(pread64, int, fd, void*, user_buf, size_t, count, loff_t, pos) {
    if (pos < 0)
        return -EINVAL;
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);
    return pread(file, user_buf, count, pos);
}

NODISCARD static ssize_t readv(struct file* file, const struct iovec* user_iov,
                               int iovcnt, uint64_t offset) {
    if (iovcnt < 0)
        return -EINVAL;
    if (iovcnt == 0)
        return 0;
    if (!is_user_range(user_iov, iovcnt * sizeof(struct iovec)))
        return -EFAULT;

    SCOPED_LOCK(file, file);
    size_t nread = 0;
    for (int i = 0; i < iovcnt; ++i) {
        struct iovec iov;
        if (copy_from_user(&iov, user_iov + i, sizeof(struct iovec)))
            return -EFAULT;
        if (iov.iov_len == 0)
            continue;
        if (!is_user_range(iov.iov_base, iov.iov_len))
            return -EFAULT;

        unsigned char* user_dest = iov.iov_base;
        size_t count = iov.iov_len;
        while (count) {
            ssize_t n = file_read(file, user_dest, count, offset);
            if (n == -EINTR) {
                if (nread == 0)
                    return -ERESTARTSYS;
                return nread;
            }
            if (IS_ERR(n)) {
                if (nread > 0)
                    return nread;
                return n;
            }
            if (n == 0)
                return nread;
            nread += n;
            user_dest += n;
            offset += n;
            count -= n;
        }
    }
    return nread;
}

SYSCALL3(readv, int, fd, const struct iovec*, user_iov, int, iovcnt) {
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);

    SCOPED_LOCK(file, file);
    ssize_t nread = readv(file, user_iov, iovcnt, file->offset);
    if (IS_OK(nread))
        file->offset += nread;
    return nread;
}

NODISCARD static ssize_t preadv2(int fd, const struct iovec* user_iov,
                                 int iovcnt, unsigned long offset_low,
                                 unsigned long offset_high, int flags) {
    (void)flags;

    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);

    uint64_t offset =
        (((uint64_t)offset_high << HALF_LONG_WIDTH) << HALF_LONG_WIDTH) |
        offset_low;
    return readv(file, user_iov, iovcnt, offset);
}

SYSCALL5(preadv, int, fd, const struct iovec*, user_iov, int, iovcnt,
         unsigned long, offset_low, unsigned long, offset_high) {
    return preadv2(fd, user_iov, iovcnt, offset_low, offset_high, 0);
}

SYSCALL6(preadv2, int, fd, const struct iovec*, user_iov, int, iovcnt,
         unsigned long, offset_low, unsigned long, offset_high, int, flags) {
    return preadv2(fd, user_iov, iovcnt, offset_low, offset_high, flags);
}

NODISCARD static ssize_t pwrite(struct file* file, const void* user_buf,
                                size_t count, uint64_t offset) {
    if (count == 0)
        return 0;
    if (!is_user_range(user_buf, count))
        return -EFAULT;
    ssize_t nwritten = file_write(file, user_buf, count, offset);
    if (nwritten == -EINTR)
        return -ERESTARTSYS;
    return nwritten;
}

SYSCALL3(write, int, fd, const void*, user_buf, size_t, count) {
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);
    SCOPED_LOCK(file, file);
    ssize_t nwritten = pwrite(file, user_buf, count, file->offset);
    if (IS_OK(nwritten))
        file->offset += nwritten;
    return nwritten;
}

SYSCALL4(pwrite64, int, fd, const void*, buf, size_t, count, loff_t, pos) {
    if (pos < 0)
        return -EINVAL;
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);
    return pwrite(file, buf, count, pos);
}

NODISCARD static ssize_t writev(struct file* file, const struct iovec* user_iov,
                                int iovcnt, uint64_t offset) {
    if (iovcnt < 0)
        return -EINVAL;
    if (iovcnt == 0)
        return 0;
    if (!is_user_range(user_iov, iovcnt * sizeof(struct iovec)))
        return -EFAULT;

    SCOPED_LOCK(file, file);
    size_t nwritten = 0;
    for (int i = 0; i < iovcnt; ++i) {
        struct iovec iov;
        if (copy_from_user(&iov, user_iov + i, sizeof(struct iovec)))
            return -EFAULT;
        if (iov.iov_len == 0)
            continue;
        if (!is_user_range(iov.iov_base, iov.iov_len))
            return -EFAULT;

        const unsigned char* user_src = iov.iov_base;
        size_t count = iov.iov_len;
        while (count) {
            ssize_t n = file_write(file, user_src, count, offset);
            if (n == -EINTR) {
                if (nwritten == 0)
                    return -ERESTARTSYS;
                return nwritten;
            }
            if (IS_ERR(n)) {
                if (nwritten > 0)
                    return nwritten;
                return n;
            }
            nwritten += n;
            user_src += n;
            offset += n;
            count -= n;
        }
    }
    return nwritten;
}

SYSCALL3(writev, int, fd, const struct iovec*, user_iov, int, iovcnt) {
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);

    SCOPED_LOCK(file, file);
    ssize_t nwritten = writev(file, user_iov, iovcnt, file->offset);
    if (IS_OK(nwritten))
        file->offset += nwritten;
    return nwritten;
}

NODISCARD static ssize_t pwritev2(int fd, const struct iovec* user_iov,
                                  int iovcnt, unsigned long offset_low,
                                  unsigned long offset_high, int flags) {
    (void)flags;

    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);

    uint64_t offset =
        (((uint64_t)offset_high << HALF_LONG_WIDTH) << HALF_LONG_WIDTH) |
        offset_low;
    return writev(file, user_iov, iovcnt, offset);
}

SYSCALL5(pwritev, int, fd, const struct iovec*, user_iov, int, iovcnt,
         unsigned long, offset_low, unsigned long, offset_high) {
    return pwritev2(fd, user_iov, iovcnt, offset_low, offset_high, 0);
}

SYSCALL6(pwritev2, int, fd, const struct iovec*, user_iov, int, iovcnt,
         unsigned long, offset_low, unsigned long, offset_high, int, flags) {
    return pwritev2(fd, user_iov, iovcnt, offset_low, offset_high, flags);
}

SYSCALL3(lseek, int, fd, off_t, offset, int, whence) {
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);
    return file_seek(file, offset, whence);
}

SYSCALL5(llseek, unsigned int, fd, unsigned long, offset_high, unsigned long,
         offset_low, loff_t*, user_result, unsigned int, whence) {
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);
    loff_t offset = ((loff_t)offset_high << 32) | offset_low;
    loff_t rc = file_seek(file, offset, whence);
    if (IS_ERR(rc))
        return (long)rc;
    if (copy_to_user(user_result, &rc, sizeof(rc)))
        return -EFAULT;
    return 0;
}

SYSCALL2(truncate, const char*, user_path, off_t, length) {
    if (length < 0)
        return -EINVAL;
    char path[PATH_MAX];
    ssize_t len = copy_pathname_from_user(path, user_path);
    if (IS_ERR(len))
        return len;
    struct file* file FREE(file) =
        ASSERT(vfs_open(BASE_CWD, path, O_WRONLY, 0));
    if (IS_ERR(file))
        return PTR_ERR(file);
    return file_truncate(file, length);
}

SYSCALL2(ftruncate, int, fd, off_t, length) {
    if (length < 0)
        return -EINVAL;
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);
    return file_truncate(file, length);
}

NODISCARD static int fsync(int fd) {
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);
    return file_sync(file, 0, UINT64_MAX);
}

SYSCALL1(fsync, int, fd) { return fsync(fd); }

SYSCALL1(fdatasync, int, fd) { return fsync(fd); }
