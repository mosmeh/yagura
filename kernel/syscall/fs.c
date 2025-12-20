#include "private.h"
#include <kernel/fs/fs.h>
#include <kernel/safe_string.h>
#include <kernel/task.h>

int sys_mount(const char* user_source, const char* user_target,
              const char* user_filesystemtype, unsigned long mountflags,
              const void* data) {
    (void)mountflags;
    (void)data;

    char source[PATH_MAX];
    int rc = copy_pathname_from_user(source, user_source);
    if (IS_ERR(rc))
        return rc;

    char target[PATH_MAX];
    rc = copy_pathname_from_user(target, user_target);
    if (IS_ERR(rc))
        return rc;

    char fs_type[SIZEOF_FIELD(struct file_system, name)];
    ssize_t fs_type_len =
        strncpy_from_user(fs_type, user_filesystemtype, sizeof(fs_type));
    if (IS_ERR(fs_type_len))
        return fs_type_len;
    if ((size_t)fs_type_len >= sizeof(fs_type)) {
        // There is no file system type with such a long name.
        return -ENODEV;
    }

    const struct file_system* fs = file_system_find(fs_type);
    if (!fs)
        return -ENODEV;
    if (fs->flags & FILE_SYSTEM_KERNEL_ONLY)
        return -EINVAL;

    return vfs_mount(fs, source, target);
}

int sys_sync(void) {
    int rc = vfs_sync();
    (void)rc;
    return 0;
}

int sys_syncfs(int fd) {
    struct file* file FREE(file) = task_ref_file(fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return mount_sync(file->inode->mount);
}
