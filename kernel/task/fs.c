#include "private.h"
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/fs/file.h>
#include <kernel/fs/inode.h>
#include <kernel/fs/path.h>
#include <kernel/task/task.h>

static struct slab fs_env_slab;

void task_fs_init(void) { SLAB_INIT(&fs_env_slab, "fs_env", struct fs_env); }

struct fs_env* fs_env_create(void) {
    struct fs_env* fs_env = ASSERT(slab_alloc(&fs_env_slab));
    if (IS_ERR(fs_env))
        return fs_env;
    *fs_env = (struct fs_env){
        .umask = 022,
        .refcount = REFCOUNT_INIT_ONE,
    };
    return fs_env;
}

struct fs_env* fs_env_clone(struct fs_env* fs_env) {
    struct fs_env* new_fs_env FREE(fs_env) = ASSERT(fs_env_create());
    if (IS_ERR(new_fs_env))
        return new_fs_env;

    SCOPED_LOCK(fs_env, fs_env);

    struct path* root FREE(path) = ASSERT(path_dup(fs_env->root));
    if (IS_ERR(root))
        return ERR_CAST(root);

    struct path* cwd FREE(path) = ASSERT(path_dup(fs_env->cwd));
    if (IS_ERR(cwd))
        return ERR_CAST(cwd);

    new_fs_env->root = TAKE_PTR(root);
    new_fs_env->cwd = TAKE_PTR(cwd);
    new_fs_env->umask = fs_env->umask;

    return TAKE_PTR(new_fs_env);
}

void __fs_env_destroy(struct fs_env* fs_env) {
    path_destroy_recursive(fs_env->cwd);
    path_destroy_recursive(fs_env->root);
    slab_free(&fs_env_slab, fs_env);
}

int fs_env_chroot(struct fs_env* fs_env, struct path* new_root) {
    ASSERT(fs_env_is_locked_by_current(fs_env));

    if (!S_ISDIR(new_root->inode->mode))
        return -ENOTDIR;

    struct path* dup_root FREE(path) = ASSERT(path_dup(new_root));
    if (IS_ERR(dup_root))
        return PTR_ERR(dup_root);

    path_destroy_recursive(fs_env->root);
    fs_env->root = TAKE_PTR(dup_root);

    return 0;
}

int fs_env_chdir(struct fs_env* fs_env, struct path* new_cwd) {
    ASSERT(fs_env_is_locked_by_current(fs_env));

    if (!S_ISDIR(new_cwd->inode->mode))
        return -ENOTDIR;

    struct path* dup_cwd FREE(path) = ASSERT(path_dup(new_cwd));
    if (IS_ERR(dup_cwd))
        return PTR_ERR(dup_cwd);

    path_destroy_recursive(fs_env->cwd);
    fs_env->cwd = TAKE_PTR(dup_cwd);

    return 0;
}

struct fd_table* fd_table_create(void) {
    struct fd_table* fd_table = kmalloc(sizeof(struct fd_table));
    if (!fd_table)
        return ERR_PTR(-ENOMEM);
    *fd_table = (struct fd_table){.refcount = REFCOUNT_INIT_ONE};
    return fd_table;
}

struct fd_table* fd_table_clone(struct fd_table* fd_table) {
    struct fd_table* new_fd_table = ASSERT(fd_table_create());
    if (IS_ERR(new_fd_table))
        return new_fd_table;

    SCOPED_LOCK(fd_table, fd_table);
    memcpy(new_fd_table->entries, fd_table->entries, sizeof(fd_table->entries));
    for (size_t i = 0; i < OPEN_MAX; ++i) {
        if (fd_table->entries[i])
            file_ref(fd_table->entries[i]);
    }
    memcpy(new_fd_table->closed_on_exec, fd_table->closed_on_exec,
           sizeof(fd_table->closed_on_exec));
    return new_fd_table;
}

void __fd_table_destroy(struct fd_table* fd_table) {
    for (size_t i = 0; i < OPEN_MAX; ++i) {
        if (fd_table->entries[i]) {
            file_unref(fd_table->entries[i]);
            fd_table->entries[i] = NULL;
        }
    }
    kfree(fd_table);
}

int fd_table_alloc_fd(struct fd_table* fd_table, int min_fd, struct file* file,
                      int flags) {
    if (min_fd >= OPEN_MAX)
        return -EMFILE;
    min_fd = MAX(min_fd, 0);

    SCOPED_LOCK(fd_table, fd_table);
    for (int i = min_fd; i < OPEN_MAX; ++i) {
        if (fd_table->entries[i])
            continue;
        fd_table->entries[i] = file_ref(file);
        ASSERT_OK(fd_table_set_flags(fd_table, i, flags));
        return i;
    }
    return -EMFILE;
}

int fd_table_set_file(struct fd_table* fd_table, int fd, struct file* file,
                      int flags) {
    if (fd < 0 || OPEN_MAX <= fd)
        return -EBADF;

    SCOPED_LOCK(fd_table, fd_table);
    struct file** entry = fd_table->entries + fd;
    file_unref(*entry);
    *entry = file_ref(file);
    ASSERT_OK(fd_table_set_flags(fd_table, fd, flags));
    return 0;
}

int fd_table_free_fd(struct fd_table* fd_table, int fd) {
    if (fd < 0 || OPEN_MAX <= fd)
        return -EBADF;

    SCOPED_LOCK(fd_table, fd_table);
    struct file** file = fd_table->entries + fd;
    if (!*file)
        return -EBADF;
    ASSERT_OK(fd_table_set_flags(fd_table, fd, 0));
    file_unref(*file);
    *file = NULL;
    return 0;
}

struct file* fd_table_ref_file(struct fd_table* fd_table, int fd) {
    if (fd < 0 || OPEN_MAX <= fd)
        return ERR_PTR(-EBADF);

    SCOPED_LOCK(fd_table, fd_table);
    struct file* file = fd_table->entries[fd];
    if (file)
        return file_ref(file);
    return ERR_PTR(-EBADF);
}

#define CLOSED_ON_EXEC_BIT(fd) (1UL << ((fd) & (ULONG_WIDTH - 1)))

static unsigned long* closed_on_exec_entry(struct fd_table* fd_table, int fd) {
    return &fd_table->closed_on_exec[fd / ULONG_WIDTH];
}

int fd_table_get_flags(struct fd_table* fd_table, int fd) {
    if (fd < 0 || OPEN_MAX <= fd)
        return -EBADF;

    SCOPED_LOCK(fd_table, fd_table);

    struct file* file = fd_table->entries[fd];
    if (!file)
        return -EBADF;

    int flags = 0;
    if (*closed_on_exec_entry(fd_table, fd) & CLOSED_ON_EXEC_BIT(fd))
        flags |= FD_CLOEXEC;

    return flags;
}

int fd_table_set_flags(struct fd_table* fd_table, int fd, int flags) {
    if (fd < 0 || OPEN_MAX <= fd)
        return -EBADF;

    SCOPED_LOCK(fd_table, fd_table);

    struct file* file = fd_table->entries[fd];
    if (!file)
        return -EBADF;

    unsigned long* entry = closed_on_exec_entry(fd_table, fd);
    if (flags & FD_CLOEXEC)
        *entry |= CLOSED_ON_EXEC_BIT(fd);
    else
        *entry &= ~CLOSED_ON_EXEC_BIT(fd);

    return 0;
}

int fd_table_close_on_exec(struct fd_table* fd_table) {
    SCOPED_LOCK(fd_table, fd_table);
    for (size_t i = 0; i < ARRAY_SIZE(fd_table->closed_on_exec); ++i) {
        for (;;) {
            int bit = __builtin_ffsl(fd_table->closed_on_exec[i]);
            if (bit == 0)
                break;
            fd_table->closed_on_exec[i] &= ~(1UL << (bit - 1));
            int fd = i * ULONG_WIDTH + (bit - 1);
            struct file** file = fd_table->entries + fd;
            ASSERT_PTR(*file);
            file_unref(*file);
            *file = NULL;
        }
    }
    return 0;
}
