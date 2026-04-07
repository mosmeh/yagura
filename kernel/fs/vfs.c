#include "private.h"
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/arch/system.h>
#include <kernel/containers/vec.h>
#include <kernel/fs/file.h>
#include <kernel/fs/inode.h>
#include <kernel/fs/path.h>
#include <kernel/fs/vfs.h>
#include <kernel/kmsg.h>
#include <kernel/lock/mutex.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/task/task.h>
#include <kernel/time.h>

static struct file_system* file_systems;

int file_system_register(struct file_system* fs) {
    ASSERT(!fs->next);

    if (file_system_find(fs->name))
        return -EEXIST;

    fs->next = file_systems;
    file_systems = fs;

    kprintf("vfs: registered filesystem %s\n", fs->name);
    return 0;
}

const struct file_system* file_system_find(const char* name) {
    for (struct file_system* it = file_systems; it; it = it->next) {
        if (!strcmp(it->name, name))
            return it;
    }
    return NULL;
}

int proc_print_filesystems(struct file* file, struct vec* vec) {
    (void)file;
    for (struct file_system* fs = file_systems; fs; fs = fs->next) {
        int rc = vec_printf(vec, "%s\n", fs->name);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}

struct mount_point {
    struct path* path;
    struct inode* host;
    struct mount* guest;
    struct mount_point* next;
};

static struct mount* mounts;
static struct mount_point* mount_points;
static struct mutex mounts_lock;

struct mount* file_system_mount(const struct file_system* fs,
                                const char* source) {
    struct mount* mount;
    if (fs->mount) {
        mount = ASSERT(fs->mount(source));
        if (IS_ERR(mount))
            return mount;
    } else {
        mount = kmalloc(sizeof(struct mount));
        if (!mount)
            return ERR_PTR(-ENOMEM);
        *mount = (struct mount){0};
    }

    SCOPED_LOCK(mutex, &mounts_lock);
    SCOPED_LOCK(mount, mount);

    if (mount->flags & MOUNT_READY) {
        // The file system returned an existing mount, so skip the rest of
        // the initialization.
        return mount;
    }

    mount->fs = fs;

    if (!mount->dev) {
        static int next_id = 1;
        int id = next_id++;
        mount->dev = makedev(UNNAMED_MAJOR, id);
    }

    mount->next = mounts;
    mounts = mount;

    mount->flags |= MOUNT_READY;

    return mount;
}

static struct inode* resolve_mounts(struct inode* host) {
    struct inode* needle = host;
    SCOPED_LOCK(mutex, &mounts_lock);
    for (;;) {
        struct mount_point* it = mount_points;
        while (it) {
            if (it->host == needle)
                break;
            it = it->next;
        }
        if (!it)
            break;
        needle = it->guest->root;
    }
    inode_ref(needle);
    return needle;
}

int vfs_mount(const struct file_system* fs, const char* source,
              const char* target) {
    SCOPED_LOCK(fs_env, current->fs_env);
    return vfs_mount_at(fs, current->fs_env->cwd, source, target);
}

int vfs_mount_at(const struct file_system* fs, const struct path* base,
                 const char* source, const char* target) {
    struct path* target_path FREE(path) =
        ASSERT(vfs_resolve_path(base, target, 0));
    if (IS_ERR(target_path))
        return PTR_ERR(target_path);

    struct inode* host = target_path->inode;
    if (!S_ISDIR(host->mode))
        return -ENOTDIR;

    struct mount_point* mp FREE(kfree) = kmalloc(sizeof(struct mount_point));
    if (!mp)
        return -ENOMEM;

    struct mount* mount = ASSERT(file_system_mount(fs, source));
    if (IS_ERR(mount))
        return PTR_ERR(mount);
    ASSERT_PTR(mount->root);

    mp->path = TAKE_PTR(target_path);
    mp->host = inode_ref(host);
    mp->guest = mount;

    SCOPED_LOCK(mutex, &mounts_lock);
    mp->next = mount_points;
    mount_points = TAKE_PTR(mp);
    return 0;
}

int proc_print_mounts(struct file* file, struct vec* vec) {
    (void)file;
    SCOPED_LOCK(fs_env, current->fs_env);
    SCOPED_LOCK(mutex, &mounts_lock);
    for (struct mount_point* it = mount_points; it; it = it->next) {
        const struct file_system* fs = it->guest->fs;
        char* path FREE(kfree) =
            path_to_string(it->path, current->fs_env->root);
        if (!path)
            return -ENOMEM;
        int rc = vec_printf(vec, "%s %s %s rw 0 0\n", fs->name, path, fs->name);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}

static bool is_absolute_path(const char* path) {
    return path[0] == PATH_SEPARATOR;
}

static struct path* resolve_path(const struct path* base, const char* pathname,
                                 int flags, unsigned symlink_depth);

static struct path* follow_symlink(const struct path* parent,
                                   struct inode* inode,
                                   const char* rest_pathname, int flags,
                                   unsigned depth) {
    ASSERT(S_ISLNK(inode->mode));
    ASSERT(depth <= SYMLOOP_MAX);

    struct file* file FREE(file) = ASSERT(inode_open(inode, O_RDONLY));
    if (IS_ERR(file))
        return ERR_CAST(file);

    char target[SYMLINK_MAX + 1];
    ssize_t target_len = file_readlink(file, target, SYMLINK_MAX);
    if (IS_ERR(target_len))
        return ERR_PTR(target_len);
    target[target_len] = '\0';

    if (!rest_pathname[0])
        return resolve_path(parent, target, flags, depth + 1);

    char* pathname FREE(kfree) =
        kmalloc(target_len + 1 + strlen(rest_pathname) + 1);
    if (!pathname)
        return ERR_PTR(-ENOMEM);
    memcpy(pathname, target, target_len);
    pathname[target_len] = PATH_SEPARATOR;
    strcpy(pathname + target_len + 1, rest_pathname);

    return resolve_path(parent, pathname, flags, depth + 1);
}

static struct path* resolve_path(const struct path* base, const char* pathname,
                                 int flags, unsigned symlink_depth) {
    if (pathname[0] == 0)
        return ERR_PTR(-ENOENT);

    struct path* path FREE(path) = NULL;
    if (is_absolute_path(pathname)) {
        struct fs_env* fs_env = current->fs_env;
        SCOPED_LOCK(fs_env, fs_env);
        path = path_dup(fs_env->root);
    } else {
        path = path_dup(base);
    }
    ASSERT(path);
    if (IS_ERR(path))
        return path;

    char* dup_pathname FREE(kfree) = kstrdup(pathname);
    if (!dup_pathname)
        return ERR_PTR(-ENOMEM);

    char* saved_ptr;
    for (const char* component =
             strtok_r(dup_pathname, PATH_SEPARATOR_STR, &saved_ptr);
         component;
         component = strtok_r(NULL, PATH_SEPARATOR_STR, &saved_ptr)) {
        if (component[0] == '\0')
            continue;
        if (component[0] == '.' && component[1] == '\0')
            continue;
        if (!strcmp(component, "..")) {
            if (!path->parent) {
                // "/.." becomes "/"
                continue;
            }
            struct path* parent = path->parent;
            path_destroy_last(path);
            path = parent;
            continue;
        }

        struct inode* inode FREE(inode) =
            ASSERT(inode_lookup(path->inode, component));

        bool has_more_components = false;
        for (char* p = saved_ptr; p && *p; ++p) {
            if (*p != PATH_SEPARATOR) {
                has_more_components = true;
                break;
            }
        }

        if ((flags & O_ALLOW_NOENT) && PTR_ERR(inode) == -ENOENT) {
            if (has_more_components)
                return ERR_PTR(-ENOENT);
            return path_join(path, NULL, component);
        }

        if (IS_ERR(inode))
            return ERR_CAST(inode);

        struct inode* resolved = resolve_mounts(inode);
        inode_unref(inode);
        inode = resolved;

        if (S_ISLNK(inode->mode)) {
            if (symlink_depth > SYMLOOP_MAX)
                return ERR_PTR(-ELOOP);

            if (has_more_components || !(flags & O_NOFOLLOW)) {
                const char* rest_pathname = strtok_r(NULL, "", &saved_ptr);
                if (!rest_pathname)
                    rest_pathname = "";
                return follow_symlink(path, inode, rest_pathname, flags,
                                      symlink_depth);
            }

            if (!(flags & O_NOFOLLOW_NOERROR))
                return ERR_PTR(-ELOOP);
        }

        struct path* joined = ASSERT(path_join(path, inode, component));
        if (IS_ERR(joined))
            return joined;
        path_destroy_recursive(path);
        path = joined;
    }

    return TAKE_PTR(path);
}

struct path* vfs_resolve_path(const struct path* base, const char* pathname,
                              int flags) {
    ASSERT(base);
    if (base == BASE_CWD) {
        SCOPED_LOCK(fs_env, current->fs_env);
        return vfs_resolve_path(current->fs_env->cwd, pathname, flags);
    }
    return resolve_path(base, pathname, flags, 0);
}

static struct path* create(const struct path* base, const char* pathname,
                           mode_t mode, bool exclusive) {
    ASSERT(mode & S_IFMT);

    int flags = O_ALLOW_NOENT;
    if (exclusive)
        flags |= O_NOFOLLOW | O_NOFOLLOW_NOERROR;
    struct path* path FREE(path) =
        ASSERT(vfs_resolve_path(base, pathname, flags));
    if (IS_ERR(path))
        return path;

    if (path->inode) {
        if (exclusive)
            return ERR_PTR(-EEXIST);
        return TAKE_PTR(path);
    }

    ASSERT_PTR(path->parent);
    ASSERT_PTR(path->parent->inode);
    if (!S_ISDIR(path->parent->inode->mode))
        return ERR_PTR(-ENOTDIR);

    struct inode* new_inode FREE(inode) =
        ASSERT(mount_create_inode(path->parent->inode->mount, mode));
    if (IS_ERR(new_inode))
        return ERR_CAST(new_inode);

    for (;;) {
        int rc = inode_link(path->parent->inode, path->basename, new_inode);
        if (IS_OK(rc)) {
            path->inode = TAKE_PTR(new_inode);
            break;
        }
        if (rc != -EEXIST || exclusive)
            return ERR_PTR(rc);
        // Another task is linking the same file. Look up the linked file.

        struct inode* inode =
            ASSERT(inode_lookup(path->parent->inode, path->basename));
        if (IS_OK(inode)) {
            path->inode = inode;
            break;
        }
        if (PTR_ERR(inode) != -ENOENT)
            return ERR_CAST(inode);
        // The file was unlinked before we could look it up. Retry linking it.
    }

    return TAKE_PTR(path);
}

struct file* vfs_open(const struct path* base, const char* pathname, int flags,
                      mode_t mode) {
    struct path* path FREE(path) =
        (flags & O_CREAT) ? create(base, pathname, mode, flags & O_EXCL)
                          : vfs_resolve_path(base, pathname, flags);
    ASSERT(path);
    if (IS_ERR(path))
        return ERR_CAST(path);

    ASSERT_PTR(path->inode);
    struct file* file = ASSERT(inode_open(path->inode, flags));
    if (IS_ERR(file))
        return file;

    file->path = TAKE_PTR(path);
    return file;
}

int vfs_stat(const struct path* base, const char* pathname, struct kstat* buf,
             int flags) {
    struct path* path FREE(path) =
        ASSERT(vfs_resolve_path(base, pathname, flags));
    if (IS_ERR(path))
        return PTR_ERR(path);
    ASSERT_PTR(path->inode);
    return inode_stat(path->inode, buf);
}

struct inode* vfs_create(const struct path* base, const char* pathname,
                         mode_t mode) {
    struct path* path = ASSERT(create(base, pathname, mode, true));
    if (IS_ERR(path))
        return ERR_CAST(path);
    struct inode* inode = inode_ref(path->inode);
    path_destroy_recursive(path);
    return inode;
}

struct inode* vfs_mknod(const struct path* base, const char* pathname,
                        mode_t mode, dev_t dev) {
    switch (mode & S_IFMT) {
    case S_IFREG:
    case S_IFCHR:
    case S_IFBLK:
    case S_IFIFO:
    case S_IFSOCK:
        break;
    default:
        return ERR_PTR(-EINVAL);
    }

    struct inode* inode = ASSERT(vfs_create(base, pathname, mode));
    if (IS_ERR(inode))
        return inode;

    if (S_ISCHR(mode) || S_ISBLK(mode))
        inode->rdev = dev;

    return inode;
}

int vfs_sync(void) {
    SCOPED_LOCK(mutex, &mounts_lock);
    for (struct mount* it = mounts; it; it = it->next) {
        int rc = mount_sync(it);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}

static void mount_root(void) {
    kprint("vfs: mounting root filesystem\n");
    const struct file_system* fs = ASSERT_PTR(file_system_find("tmpfs"));
    struct mount* mount = ASSERT_PTR(file_system_mount(fs, "tmpfs"));
    struct path* root FREE(path) = ASSERT_PTR(path_create_root(mount->root));

    SCOPED_LOCK(fs_env, current->fs_env);
    ASSERT_OK(fs_env_chroot(current->fs_env, root));
    ASSERT_OK(fs_env_chdir(current->fs_env, root));
}

static void schedule_sync(void);

static void sync(struct work* work) {
    (void)work;
    int rc = vfs_sync();
    if (IS_ERR(rc))
        kprintf("vfs: sync failed (error %d)\n", rc);
    schedule_sync();
}

static void submit_sync(struct timer* timer) {
    (void)timer;
    static struct work work;
    workqueue_submit(global_workqueue, &work, sync);
}

static struct timer sync_timer;

static void schedule_sync(void) {
    static const struct timespec sync_interval = {.tv_sec = 5};
    timer_arm_after(&sync_timer, &sync_interval);
}

void vfs_init(void) {
    ramfs_init();
    proc_init();
    mount_root();
    initramfs_populate_root_fs(boot_params.initramfs_addr,
                               boot_params.initramfs_size);

    ASSERT_OK(timer_init(&sync_timer, CLOCK_MONOTONIC, submit_sync));
    schedule_sync();
}
