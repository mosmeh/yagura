#include "private.h"
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/fs/file.h>
#include <kernel/fs/path.h>
#include <kernel/task/task.h>

static struct slab fs_slab;

void task_fs_init(void) { slab_init(&fs_slab, "fs", sizeof(struct fs)); }

struct fs* fs_create(void) {
    struct fs* fs = slab_alloc(&fs_slab);
    if (IS_ERR(fs))
        return fs;
    *fs = (struct fs){
        .umask = 022,
        .refcount = REFCOUNT_INIT_ONE,
    };
    return fs;
}

struct fs* fs_clone(struct fs* fs) {
    struct fs* new_fs FREE(fs) = fs_create();
    if (IS_ERR(ASSERT(new_fs)))
        return new_fs;

    SCOPED_LOCK(fs, fs);

    struct path* root FREE(path) = path_dup(fs->root);
    if (IS_ERR(ASSERT(root)))
        return ERR_CAST(root);

    struct path* cwd FREE(path) = path_dup(fs->cwd);
    if (IS_ERR(ASSERT(cwd)))
        return ERR_CAST(cwd);

    new_fs->root = TAKE_PTR(root);
    new_fs->cwd = TAKE_PTR(cwd);
    new_fs->umask = fs->umask;

    return TAKE_PTR(new_fs);
}

void __fs_destroy(struct fs* fs) {
    path_destroy_recursive(fs->cwd);
    path_destroy_recursive(fs->root);
    slab_free(&fs_slab, fs);
}

int fs_chroot(struct fs* fs, struct path* new_root) {
    ASSERT(fs_is_locked_by_current(fs));

    if (!S_ISDIR(new_root->inode->mode))
        return -ENOTDIR;

    struct path* dup_root FREE(path) = path_dup(new_root);
    if (IS_ERR(ASSERT(dup_root)))
        return PTR_ERR(dup_root);

    path_destroy_recursive(fs->root);
    fs->root = TAKE_PTR(dup_root);

    return 0;
}

int fs_chdir(struct fs* fs, struct path* new_cwd) {
    ASSERT(fs_is_locked_by_current(fs));

    if (!S_ISDIR(new_cwd->inode->mode))
        return -ENOTDIR;

    struct path* dup_cwd FREE(path) = path_dup(new_cwd);
    if (IS_ERR(ASSERT(dup_cwd)))
        return PTR_ERR(dup_cwd);

    path_destroy_recursive(fs->cwd);
    fs->cwd = TAKE_PTR(dup_cwd);

    return 0;
}

struct files* files_create(void) {
    struct files* files = kmalloc(sizeof(struct files));
    if (!files)
        return ERR_PTR(-ENOMEM);
    *files = (struct files){.refcount = REFCOUNT_INIT_ONE};
    return files;
}

struct files* files_clone(struct files* files) {
    struct files* new_files = files_create();
    if (IS_ERR(ASSERT(new_files)))
        return new_files;

    SCOPED_LOCK(files, files);
    memcpy(new_files->entries, files->entries, sizeof(files->entries));
    for (size_t i = 0; i < OPEN_MAX; ++i) {
        if (files->entries[i])
            file_ref(files->entries[i]);
    }
    memcpy(new_files->closed_on_exec, files->closed_on_exec,
           sizeof(files->closed_on_exec));
    return new_files;
}

void __files_destroy(struct files* files) {
    for (size_t i = 0; i < OPEN_MAX; ++i) {
        if (files->entries[i]) {
            file_unref(files->entries[i]);
            files->entries[i] = NULL;
        }
    }
    kfree(files);
}

int files_alloc_fd(struct files* files, int min_fd, struct file* file,
                   int flags) {
    if (min_fd >= OPEN_MAX)
        return -EMFILE;
    min_fd = MAX(min_fd, 0);

    SCOPED_LOCK(files, files);
    for (int i = min_fd; i < OPEN_MAX; ++i) {
        if (files->entries[i])
            continue;
        files->entries[i] = file_ref(file);
        ASSERT_OK(files_set_flags(files, i, flags));
        return i;
    }
    return -EMFILE;
}

int files_set_file(struct files* files, int fd, struct file* file, int flags) {
    if (fd < 0 || OPEN_MAX <= fd)
        return -EBADF;

    SCOPED_LOCK(files, files);
    struct file** entry = files->entries + fd;
    file_unref(*entry);
    *entry = file_ref(file);
    ASSERT_OK(files_set_flags(files, fd, flags));
    return 0;
}

int files_free_fd(struct files* files, int fd) {
    if (fd < 0 || OPEN_MAX <= fd)
        return -EBADF;

    SCOPED_LOCK(files, files);
    struct file** file = files->entries + fd;
    if (!*file)
        return -EBADF;
    ASSERT_OK(files_set_flags(files, fd, 0));
    file_unref(*file);
    *file = NULL;
    return 0;
}

struct file* files_ref_file(struct files* files, int fd) {
    if (fd < 0 || OPEN_MAX <= fd)
        return ERR_PTR(-EBADF);

    SCOPED_LOCK(files, files);
    struct file* file = files->entries[fd];
    if (file)
        return file_ref(file);
    return ERR_PTR(-EBADF);
}

#define CLOSED_ON_EXEC_BIT(fd) (1UL << ((fd) & (ULONG_WIDTH - 1)))

static unsigned long* closed_on_exec_entry(struct files* files, int fd) {
    return &files->closed_on_exec[fd / ULONG_WIDTH];
}

int files_get_flags(struct files* files, int fd) {
    if (fd < 0 || OPEN_MAX <= fd)
        return -EBADF;

    SCOPED_LOCK(files, files);

    struct file* file = files->entries[fd];
    if (!file)
        return -EBADF;

    int flags = 0;
    if (*closed_on_exec_entry(files, fd) & CLOSED_ON_EXEC_BIT(fd))
        flags |= FD_CLOEXEC;

    return flags;
}

int files_set_flags(struct files* files, int fd, int flags) {
    if (fd < 0 || OPEN_MAX <= fd)
        return -EBADF;

    SCOPED_LOCK(files, files);

    struct file* file = files->entries[fd];
    if (!file)
        return -EBADF;

    unsigned long* entry = closed_on_exec_entry(files, fd);
    if (flags & FD_CLOEXEC)
        *entry |= CLOSED_ON_EXEC_BIT(fd);
    else
        *entry &= ~CLOSED_ON_EXEC_BIT(fd);

    return 0;
}

int files_close_on_exec(struct files* files) {
    SCOPED_LOCK(files, files);
    for (size_t i = 0; i < ARRAY_SIZE(files->closed_on_exec); ++i) {
        for (;;) {
            int bit = __builtin_ffsl(files->closed_on_exec[i]);
            if (bit == 0)
                break;
            files->closed_on_exec[i] &= ~(1UL << (bit - 1));
            int fd = i * ULONG_WIDTH + (bit - 1);
            struct file** file = files->entries + fd;
            ASSERT(*file);
            file_unref(*file);
            *file = NULL;
        }
    }
    return 0;
}
