#include "private.h"
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/uio.h>
#include <kernel/fs/file.h>
#include <kernel/memory/safe_string.h>
#include <kernel/task/task.h>

long sys_read(int fd, void* user_buf, size_t count) {
    if (!user_buf || !is_user_range(user_buf, count))
        return -EFAULT;
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    int rc = file_read(file, user_buf, count);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

long sys_ia32_pread64(int fd, void* user_buf, size_t count, uint32_t pos_lo,
                      uint32_t pos_hi) {
    if (!user_buf || !is_user_range(user_buf, count))
        return -EFAULT;
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    uint64_t pos = ((uint64_t)pos_hi << 32) | pos_lo;
    int rc = file_pread(file, user_buf, count, pos);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

NODISCARD static ssize_t read_all(struct file* file, void* user_buffer,
                                  size_t count) {
    size_t nread = 0;
    unsigned char* user_dest = user_buffer;
    while (count) {
        ssize_t n = file_read(file, user_dest, count);
        if (n == -EINTR)
            return -EINTR;
        if (IS_ERR(n))
            return n;
        if (n == 0)
            break;
        nread += n;
        user_dest += n;
        count -= n;
    }
    return nread;
}

long sys_readv(int fd, const struct iovec* user_iov, int iovcnt) {
    if (!user_iov || !is_user_range(user_iov, iovcnt * sizeof(struct iovec)))
        return -EFAULT;

    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    SCOPED_LOCK(file, file);
    size_t nread = 0;
    for (int i = 0; i < iovcnt; ++i) {
        struct iovec iov;
        if (copy_from_user(&iov, user_iov + i, sizeof(struct iovec)))
            return -EFAULT;
        if (!is_user_range(iov.iov_base, iov.iov_len))
            return -EFAULT;
        ssize_t n = read_all(file, iov.iov_base, iov.iov_len);
        if (n == -EINTR && nread == 0)
            return -ERESTARTSYS;
        if (IS_ERR(n))
            return n;
        nread += n;
    }
    return nread;
}

long sys_write(int fd, const void* user_buf, size_t count) {
    if (!user_buf || !is_user_range(user_buf, count))
        return -EFAULT;
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    int rc = file_write(file, user_buf, count);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

long sys_ia32_pwrite64(int fd, const void* user_buf, size_t count,
                       uint32_t pos_lo, uint32_t pos_hi) {
    if (!user_buf || !is_user_range(user_buf, count))
        return -EFAULT;
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    uint64_t pos = ((uint64_t)pos_hi << 32) | pos_lo;
    int rc = file_pwrite(file, user_buf, count, pos);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

NODISCARD static ssize_t write_all(struct file* file, const void* user_buffer,
                                   size_t count) {
    size_t nwritten = 0;
    const unsigned char* user_src = user_buffer;
    while (count) {
        ssize_t n = file_write(file, user_src, count);
        if (n == -EINTR)
            return -EINTR;
        if (IS_ERR(n))
            return n;
        if (n == 0)
            break;
        nwritten += n;
        user_src += n;
        count -= n;
    }
    return nwritten;
}

long sys_writev(int fd, const struct iovec* user_iov, int iovcnt) {
    if (!user_iov || !is_user_range(user_iov, iovcnt * sizeof(struct iovec)))
        return -EFAULT;

    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    SCOPED_LOCK(file, file);
    size_t nwritten = 0;
    for (int i = 0; i < iovcnt; ++i) {
        struct iovec iov;
        if (copy_from_user(&iov, user_iov + i, sizeof(struct iovec)))
            return -EFAULT;
        if (!is_user_range(iov.iov_base, iov.iov_len))
            return -EFAULT;
        ssize_t n = write_all(file, iov.iov_base, iov.iov_len);
        if (n == -EINTR && nwritten == 0)
            return -ERESTARTSYS;
        if (IS_ERR(n))
            return n;
        nwritten += n;
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
        return (int)rc;
    if (copy_to_user(user_result, &rc, sizeof(rc)))
        return -EFAULT;
    return 0;
}

NODISCARD static long truncate(const char* user_path, uint64_t length) {
    char path[PATH_MAX];
    int rc = copy_pathname_from_user(path, user_path);
    if (IS_ERR(rc))
        return rc;
    struct file* file FREE(file) = vfs_open(path, O_WRONLY, 0);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return file_truncate(file, length);
}

NODISCARD static long ftruncate(int fd, uint64_t length) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return file_truncate(file, length);
}

long sys_truncate(const char* user_path, off_t length) {
    return truncate(user_path, length);
}

long sys_ftruncate(int fd, off_t length) { return ftruncate(fd, length); }

long sys_ia32_truncate64(const char* user_path, unsigned long offset_low,
                         unsigned long offset_high) {
    return truncate(user_path, ((uint64_t)offset_high << 32) | offset_low);
}

long sys_ia32_ftruncate64(int fd, unsigned long offset_low,
                          unsigned long offset_high) {
    return ftruncate(fd, ((uint64_t)offset_high << 32) | offset_low);
}

long sys_fsync(int fd) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return file_sync(file, 0, UINT64_MAX);
}

long sys_fdatasync(int fd) { return sys_fsync(fd); }
