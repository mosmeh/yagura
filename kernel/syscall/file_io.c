#include "private.h"
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/uio.h>
#include <kernel/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task.h>

ssize_t sys_read(int fd, void* user_buf, size_t count) {
    if (!user_buf || !is_user_range(user_buf, count))
        return -EFAULT;
    struct file* file FREE(file) = task_ref_file(fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    int rc = file_read(file, user_buf, count);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

ssize_t sys_ia32_pread64(int fd, void* user_buf, size_t count, uint32_t pos_lo,
                         uint32_t pos_hi) {
    if (!user_buf || !is_user_range(user_buf, count))
        return -EFAULT;
    struct file* file FREE(file) = task_ref_file(fd);
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

ssize_t sys_readv(int fd, const struct iovec* user_iov, int iovcnt) {
    if (!user_iov || !is_user_range(user_iov, iovcnt * sizeof(struct iovec)))
        return -EFAULT;
    struct file* file FREE(file) = task_ref_file(fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    mutex_lock(&file->lock);
    ssize_t ret = 0;
    for (int i = 0; i < iovcnt; ++i) {
        struct iovec iov;
        if (copy_from_user(&iov, user_iov + i, sizeof(struct iovec))) {
            ret = -EFAULT;
            break;
        }
        if (!is_user_range(iov.iov_base, iov.iov_len)) {
            ret = -EFAULT;
            break;
        }
        ssize_t nread = read_all(file, iov.iov_base, iov.iov_len);
        if (nread == -EINTR) {
            if (ret == 0)
                ret = -ERESTARTSYS;
            break;
        }
        if (IS_ERR(nread)) {
            ret = nread;
            break;
        }
        ret += nread;
    }
    mutex_unlock(&file->lock);
    return ret;
}

ssize_t sys_write(int fd, const void* user_buf, size_t count) {
    if (!user_buf || !is_user_range(user_buf, count))
        return -EFAULT;
    struct file* file FREE(file) = task_ref_file(fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    int rc = file_write(file, user_buf, count);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

ssize_t sys_ia32_pwrite64(int fd, const void* user_buf, size_t count,
                          uint32_t pos_lo, uint32_t pos_hi) {
    if (!user_buf || !is_user_range(user_buf, count))
        return -EFAULT;
    struct file* file FREE(file) = task_ref_file(fd);
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

ssize_t sys_writev(int fd, const struct iovec* user_iov, int iovcnt) {
    if (!user_iov || !is_user_range(user_iov, iovcnt * sizeof(struct iovec)))
        return -EFAULT;
    struct file* file FREE(file) = task_ref_file(fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    mutex_lock(&file->lock);
    ssize_t ret = 0;
    for (int i = 0; i < iovcnt; ++i) {
        struct iovec iov;
        if (copy_from_user(&iov, user_iov + i, sizeof(struct iovec))) {
            ret = -EFAULT;
            break;
        }
        if (!is_user_range(iov.iov_base, iov.iov_len)) {
            ret = -EFAULT;
            break;
        }
        ssize_t nwritten = write_all(file, iov.iov_base, iov.iov_len);
        if (nwritten == -EINTR) {
            if (ret == 0)
                ret = -ERESTARTSYS;
            break;
        }
        if (IS_ERR(nwritten)) {
            ret = nwritten;
            break;
        }
        ret += nwritten;
    }
    mutex_unlock(&file->lock);
    return ret;
}

off_t sys_lseek(int fd, off_t offset, int whence) {
    struct file* file FREE(file) = task_ref_file(fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return file_seek(file, offset, whence);
}

int sys_llseek(unsigned int fd, unsigned long offset_high,
               unsigned long offset_low, loff_t* user_result,
               unsigned int whence) {
    struct file* file FREE(file) = task_ref_file(fd);
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

NODISCARD static int truncate(const char* user_path, uint64_t length) {
    char path[PATH_MAX];
    int rc = copy_pathname_from_user(path, user_path);
    if (IS_ERR(rc))
        return rc;
    struct file* file FREE(file) = vfs_open(path, O_WRONLY, 0);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return file_truncate(file, length);
}

NODISCARD static int ftruncate(int fd, uint64_t length) {
    struct file* file FREE(file) = task_ref_file(fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return file_truncate(file, length);
}

int sys_truncate(const char* user_path, off_t length) {
    return truncate(user_path, length);
}

int sys_ftruncate(int fd, off_t length) { return ftruncate(fd, length); }

int sys_ia32_truncate64(const char* user_path, unsigned long offset_low,
                        unsigned long offset_high) {
    return truncate(user_path, ((uint64_t)offset_high << 32) | offset_low);
}

int sys_ia32_ftruncate64(int fd, unsigned long offset_low,
                         unsigned long offset_high) {
    return ftruncate(fd, ((uint64_t)offset_high << 32) | offset_low);
}

int sys_fsync(int fd) {
    struct file* file FREE(file) = task_ref_file(fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return file_sync(file, 0, UINT64_MAX);
}

int sys_fdatasync(int fd) { return sys_fsync(fd); }
