#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/containers/vec.h>
#include <kernel/fs/file.h>
#include <kernel/fs/fs.h>
#include <kernel/fs/path.h>
#include <kernel/kmsg.h>
#include <kernel/lock.h>
#include <kernel/memory/memory.h>
#include <kernel/multiboot.h>
#include <kernel/panic.h>
#include <kernel/task/task.h>

struct file_system* file_systems;

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
        mount = fs->mount(source);
        if (IS_ERR(ASSERT(mount)))
            return mount;
    } else {
        mount = kmalloc(sizeof(struct mount));
        if (!mount)
            return ERR_PTR(-ENOMEM);
        *mount = (struct mount){0};
    }

    mount->fs = fs;

    if (!mount->dev) {
        static int next_id = 1;
        int id = next_id++;
        mount->dev = makedev(UNNAMED_MAJOR, id);
    }

    SCOPED_LOCK(mutex, &mounts_lock);
    mount->next = mounts;
    mounts = mount;
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
    SCOPED_LOCK(fs, current->fs);
    return vfs_mount_at(fs, current->fs->cwd, source, target);
}

int vfs_mount_at(const struct file_system* fs, const struct path* base,
                 const char* source, const char* target) {
    struct path* target_path FREE(path) = vfs_resolve_path_at(base, target, 0);
    if (IS_ERR(ASSERT(target_path)))
        return PTR_ERR(target_path);

    struct inode* host = target_path->inode;
    if (!S_ISDIR(host->mode))
        return -ENOTDIR;

    struct mount_point* mp FREE(kfree) = kmalloc(sizeof(struct mount_point));
    if (!mp)
        return -ENOMEM;

    struct mount* mount = file_system_mount(fs, source);
    if (IS_ERR(ASSERT(mount)))
        return PTR_ERR(mount);
    ASSERT(mount->root);

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
    SCOPED_LOCK(mutex, &mounts_lock);
    for (struct mount_point* it = mount_points; it; it = it->next) {
        const struct file_system* fs = it->guest->fs;
        char* path FREE(kfree) = path_to_string(it->path);
        if (!path)
            return -ENOMEM;
        vec_printf(vec, "%s %s %s rw 0 0\n", fs->name, path, fs->name);
    }
    return 0;
}

static bool is_absolute_path(const char* path) {
    return path[0] == PATH_SEPARATOR;
}

static struct path* resolve_path_at(const struct path* base,
                                    const char* pathname, int flags,
                                    unsigned symlink_depth);

static struct path* follow_symlink(const struct path* parent,
                                   struct inode* inode,
                                   const char* rest_pathname, int flags,
                                   unsigned depth) {
    ASSERT(S_ISLNK(inode->mode));
    ASSERT(depth <= SYMLOOP_MAX);

    struct file* file FREE(file) = inode_open(inode, O_RDONLY);
    if (IS_ERR(ASSERT(file)))
        return ERR_CAST(file);

    char target[SYMLINK_MAX];
    ssize_t target_len = file_readlink(file, target, SYMLINK_MAX);
    if (IS_ERR(target_len))
        return ERR_PTR(target_len);

    char* pathname FREE(kfree) =
        kmalloc(target_len + 1 + strlen(rest_pathname) + 1);
    if (!pathname)
        return ERR_PTR(-ENOMEM);
    memcpy(pathname, target, target_len);
    pathname[target_len] = PATH_SEPARATOR;
    strcpy(pathname + target_len + 1, rest_pathname);

    return resolve_path_at(parent, pathname, flags, depth + 1);
}

static struct path* resolve_path_at(const struct path* base,
                                    const char* pathname, int flags,
                                    unsigned symlink_depth) {
    struct path* path FREE(path) = NULL;
    if (is_absolute_path(pathname)) {
        struct fs* fs = current->fs;
        SCOPED_LOCK(fs, fs);
        path = path_dup(fs->root);
    } else {
        path = path_dup(base);
    }
    if (IS_ERR(ASSERT(path)))
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

        struct inode* inode FREE(inode) = inode_lookup(path->inode, component);

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

        if (IS_ERR(ASSERT(inode)))
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
                    rest_pathname = ".";
                return follow_symlink(path, inode, rest_pathname, flags,
                                      symlink_depth);
            }

            if (!(flags & O_NOFOLLOW_NOERROR))
                return ERR_PTR(-ELOOP);
        }

        struct path* joined = path_join(path, inode, component);
        if (IS_ERR(ASSERT(joined)))
            return joined;
        path_destroy_recursive(path);
        path = joined;
    }

    return TAKE_PTR(path);
}

struct path* vfs_resolve_path(const char* pathname, int flags) {
    SCOPED_LOCK(fs, current->fs);
    return vfs_resolve_path_at(current->fs->cwd, pathname, flags);
}

struct path* vfs_resolve_path_at(const struct path* base, const char* pathname,
                                 int flags) {
    return resolve_path_at(base, pathname, flags, 0);
}

static struct path* create_at(const struct path* base, const char* pathname,
                              mode_t mode, bool exclusive) {
    ASSERT(mode & S_IFMT);

    struct path* path FREE(path) =
        vfs_resolve_path_at(base, pathname, O_ALLOW_NOENT);
    if (IS_ERR(ASSERT(path)))
        return ERR_CAST(path);

    if (path->inode) {
        if (exclusive)
            return ERR_PTR(-EEXIST);
        return TAKE_PTR(path);
    }

    ASSERT(path->parent);
    ASSERT(path->parent->inode);
    if (!S_ISDIR(path->parent->inode->mode))
        return ERR_PTR(-ENOTDIR);

    struct inode* new_inode FREE(inode) =
        mount_create_inode(path->parent->inode->mount, mode);
    if (IS_ERR(ASSERT(new_inode)))
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

        struct inode* inode = inode_lookup(path->parent->inode, path->basename);
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

struct file* vfs_open(const char* pathname, int flags, mode_t mode) {
    SCOPED_LOCK(fs, current->fs);
    return vfs_open_at(current->fs->cwd, pathname, flags, mode);
}

struct file* vfs_open_at(const struct path* base, const char* pathname,
                         int flags, mode_t mode) {
    struct path* path FREE(path) =
        (flags & O_CREAT) ? create_at(base, pathname, mode, flags & O_EXCL)
                          : vfs_resolve_path_at(base, pathname, flags);
    if (IS_ERR(ASSERT(path)))
        return ERR_CAST(path);

    ASSERT(path->inode);
    return inode_open(path->inode, flags);
}

int vfs_stat(const char* pathname, struct kstat* buf, int flags) {
    SCOPED_LOCK(fs, current->fs);
    return vfs_stat_at(current->fs->cwd, pathname, buf, flags);
}

int vfs_stat_at(const struct path* base, const char* pathname,
                struct kstat* buf, int flags) {
    struct path* path FREE(path) = vfs_resolve_path_at(base, pathname, flags);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);
    ASSERT(path->inode);
    return inode_stat(path->inode, buf);
}

struct inode* vfs_create(const char* pathname, mode_t mode) {
    SCOPED_LOCK(fs, current->fs);
    return vfs_create_at(current->fs->cwd, pathname, mode);
}

struct inode* vfs_create_at(const struct path* base, const char* pathname,
                            mode_t mode) {
    struct path* path = create_at(base, pathname, mode, true);
    if (IS_ERR(ASSERT(path)))
        return ERR_CAST(path);
    struct inode* inode = inode_ref(path->inode);
    path_destroy_recursive(path);
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

void tmpfs_init(void);
void proc_init(void);
void initrd_populate_root_fs(uintptr_t phys_addr, size_t size);

void vfs_init(const multiboot_module_t* initrd_mod) {
    tmpfs_init();
    proc_init();

    kprint("vfs: mounting root filesystem\n");
    const struct file_system* fs = file_system_find("tmpfs");
    ASSERT(fs);
    struct mount* mount = file_system_mount(fs, "tmpfs");
    ASSERT_PTR(mount);

    struct path* root FREE(path) = path_create_root(mount->root);
    ASSERT_PTR(root);

    {
        SCOPED_LOCK(fs, current->fs);
        ASSERT_OK(fs_chroot(current->fs, root));
        ASSERT_OK(fs_chdir(current->fs, root));
    }

    kprintf("vfs: populating root fs with initrd at P%#x - P%#x\n",
            initrd_mod->mod_start, initrd_mod->mod_end);
    initrd_populate_root_fs(initrd_mod->mod_start,
                            initrd_mod->mod_end - initrd_mod->mod_start);
}
