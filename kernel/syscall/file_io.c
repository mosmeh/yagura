#include <kernel/api/fcntl.h>
#include <kernel/api/sys/uio.h>
#include <kernel/fs/file.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>

long sys_read(int fd, void* user_buf, size_t count) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    if (count == 0)
        return 0;
    if (!is_user_range(user_buf, count))
        return -EFAULT;
    ssize_t nread = file_read(file, user_buf, count);
    if (nread == -EINTR)
        return -ERESTARTSYS;
    return nread;
}

long sys_readv(int fd, const struct iovec* user_iov, int iovcnt) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

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
            ssize_t n = file_read(file, user_dest, count);
            if (n == -EINTR) {
                if (nread == 0)
                    return -ERESTARTSYS;
                return nread;
            }
            if (IS_ERR(n))
                return n;
            if (n == 0)
                return nread;
            nread += n;
            user_dest += n;
            count -= n;
        }
    }
    return nread;
}

long sys_write(int fd, const void* user_buf, size_t count) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    if (count == 0)
        return 0;
    if (!is_user_range(user_buf, count))
        return -EFAULT;
    ssize_t nwritten = file_write(file, user_buf, count);
    if (nwritten == -EINTR)
        return -ERESTARTSYS;
    return nwritten;
}

long sys_writev(int fd, const struct iovec* user_iov, int iovcnt) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

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
            ssize_t n = file_write(file, user_src, count);
            if (n == -EINTR) {
                if (nwritten == 0)
                    return -ERESTARTSYS;
                return nwritten;
            }
            if (IS_ERR(n))
                return n;
            if (n == 0)
                return nwritten;
            nwritten += n;
            user_src += n;
            count -= n;
        }
    }
    return nwritten;
}

long sys_lseek(int fd, off_t offset, int whence) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return file_seek(file, offset, whence);
}

long sys_llseek(unsigned int fd, unsigned long offset_high,
                unsigned long offset_low, loff_t* user_result,
                unsigned int whence) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    loff_t offset = ((loff_t)offset_high << 32) | offset_low;
    loff_t rc = file_seek(file, offset, whence);
    if (IS_ERR(rc))
        return (long)rc;
    if (copy_to_user(user_result, &rc, sizeof(rc)))
        return -EFAULT;
    return 0;
}

long sys_truncate(const char* user_path, off_t length) {
    if (length < 0)
        return -EINVAL;
    char path[PATH_MAX];
    ssize_t len = copy_pathname_from_user(path, user_path);
    if (IS_ERR(len))
        return len;
    struct file* file FREE(file) = vfs_open(path, O_WRONLY, 0);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return file_truncate(file, length);
}

long sys_ftruncate(int fd, off_t length) {
    if (length < 0)
        return -EINVAL;
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return file_truncate(file, length);
}

long sys_fsync(int fd) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return file_sync(file, 0, UINT64_MAX);
}

long sys_fdatasync(int fd) { return sys_fsync(fd); }
