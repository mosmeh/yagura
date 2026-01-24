#include <kernel/api/fcntl.h>
#include <kernel/fs/file.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>

long sys_ia32_pread64(int fd, void* user_buf, size_t count, uint32_t pos_lo,
                      uint32_t pos_hi) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    if (count == 0)
        return 0;
    if (!is_user_range(user_buf, count))
        return -EFAULT;
    uint64_t pos = ((uint64_t)pos_hi << 32) | pos_lo;
    int rc = file_pread(file, user_buf, count, pos);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

long sys_ia32_pwrite64(int fd, const void* user_buf, size_t count,
                       uint32_t pos_lo, uint32_t pos_hi) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    if (count == 0)
        return 0;
    if (!is_user_range(user_buf, count))
        return -EFAULT;
    uint64_t pos = ((uint64_t)pos_hi << 32) | pos_lo;
    int rc = file_pwrite(file, user_buf, count, pos);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

long sys_ia32_truncate64(const char* user_path, unsigned long offset_low,
                         unsigned long offset_high) {
    char path[PATH_MAX];
    ssize_t len = copy_pathname_from_user(path, user_path);
    if (IS_ERR(len))
        return len;
    struct file* file FREE(file) = vfs_open(path, O_WRONLY, 0);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return file_truncate(file, ((uint64_t)offset_high << 32) | offset_low);
}

long sys_ia32_ftruncate64(int fd, unsigned long offset_low,
                          unsigned long offset_high) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return file_truncate(file, ((uint64_t)offset_high << 32) | offset_low);
}
