#include "fs.h"
#include "path.h"
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/kmsg.h>
#include <kernel/lock.h>
#include <kernel/memory/memory.h>
#include <kernel/multiboot.h>
#include <kernel/panic.h>
#include <kernel/task.h>

static struct inode* root;

struct path* vfs_get_root(void) {
    ASSERT(root);
    struct path* path = kmalloc(sizeof(struct path));
    if (!path)
        return ERR_PTR(-ENOMEM);
    *path = (struct path){.inode = root};
    inode_ref(root);
    return path;
}

struct file_system* file_systems;

int file_system_register(struct file_system* fs) {
    ASSERT(!fs->next);

    if (file_system_find(fs->name))
        return -EEXIST;

    static const struct fs_ops noop_fs_ops = {0};
    if (!fs->fs_ops)
        fs->fs_ops = &noop_fs_ops;

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
    struct inode* host;
    struct mount* guest;
    struct mount_point* next;
};

static struct mount* mounts;
static struct mount_point* mount_points;
static struct mutex mount_lock;

struct mount* file_system_mount(const struct file_system* fs,
                                const char* source) {
    struct mount* mount;
    if (fs->fs_ops->mount) {
        mount = fs->fs_ops->mount(source);
        if (IS_ERR(mount))
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

    mutex_lock(&mount_lock);
    mount->next = mounts;
    mounts = mount;
    mutex_unlock(&mount_lock);

    return mount;
}

static struct inode* resolve_mounts(struct inode* host) {
    struct inode* needle = host;
    mutex_lock(&mount_lock);
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
    if (needle != host)
        inode_ref(needle);
    mutex_unlock(&mount_lock);
    return needle;
}

int vfs_mount(const struct file_system* fs, const char* source,
              const char* target) {
    mutex_lock(&current->fs->lock);
    int ret = vfs_mount_at(fs, current->fs->cwd, source, target);
    mutex_unlock(&current->fs->lock);
    return ret;
}

int vfs_mount_at(const struct file_system* fs, const struct path* base,
                 const char* source, const char* target) {
    struct path* target_path = vfs_resolve_path_at(base, target, 0);
    if (IS_ERR(target_path))
        return PTR_ERR(target_path);

    struct inode* host = path_into_inode(target_path);
    if (!S_ISDIR(host->mode)) {
        inode_unref(host);
        return -ENOTDIR;
    }

    struct mount_point* mp = kmalloc(sizeof(struct mount_point));
    if (!mp) {
        inode_unref(host);
        return -ENOMEM;
    }

    struct mount* mount = file_system_mount(fs, source);
    if (IS_ERR(mount)) {
        inode_unref(host);
        kfree(mp);
        return PTR_ERR(mount);
    }
    ASSERT(mount->root);

    mp->host = host;
    mp->guest = mount;

    mutex_lock(&mount_lock);
    mp->next = mount_points;
    mount_points = mp;
    mutex_unlock(&mount_lock);

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

    struct file* file = inode_open(inode, O_RDONLY);
    if (IS_ERR(file))
        return ERR_CAST(file);

    char target[SYMLINK_MAX];
    ssize_t target_len = file_read_to_end(file, target, SYMLINK_MAX);
    file_unref(file);
    if (IS_ERR(target_len))
        return ERR_PTR(target_len);

    char* pathname = kmalloc(target_len + 1 + strlen(rest_pathname) + 1);
    if (!pathname)
        return ERR_PTR(-ENOMEM);
    memcpy(pathname, target, target_len);
    pathname[target_len] = PATH_SEPARATOR;
    strcpy(pathname + target_len + 1, rest_pathname);

    struct path* path = resolve_path_at(parent, pathname, flags, depth + 1);
    kfree(pathname);
    return path;
}

static struct path* resolve_path_at(const struct path* base,
                                    const char* pathname, int flags,
                                    unsigned symlink_depth) {
    struct path* path =
        is_absolute_path(pathname) ? vfs_get_root() : path_dup(base);
    if (IS_ERR(path))
        return path;

    char* dup_pathname = kstrdup(pathname);
    if (!dup_pathname) {
        path_destroy_recursive(path);
        return ERR_PTR(-ENOMEM);
    }

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

        inode_ref(path->inode);
        struct inode* inode = inode_lookup(path->inode, component);

        bool has_more_components = false;
        for (char* p = saved_ptr; p && *p; ++p) {
            if (*p != PATH_SEPARATOR) {
                has_more_components = true;
                break;
            }
        }

        if ((flags & O_ALLOW_NOENT) && PTR_ERR(inode) == -ENOENT) {
            if (has_more_components) {
                path_destroy_recursive(path);
                kfree(dup_pathname);
                return ERR_PTR(-ENOENT);
            }
            struct path* joined = path_join(path, NULL, component);
            if (IS_ERR(joined))
                path_destroy_recursive(path);
            kfree(dup_pathname);
            return joined;
        }

        if (IS_ERR(inode)) {
            path_destroy_recursive(path);
            kfree(dup_pathname);
            return ERR_CAST(inode);
        }

        inode = resolve_mounts(inode);

        if (S_ISLNK(inode->mode)) {
            if (symlink_depth > SYMLOOP_MAX) {
                inode_unref(inode);
                path_destroy_recursive(path);
                kfree(dup_pathname);
                return ERR_PTR(-ELOOP);
            }

            if (has_more_components || !(flags & O_NOFOLLOW)) {
                const char* rest_pathname = strtok_r(NULL, "", &saved_ptr);
                if (!rest_pathname)
                    rest_pathname = ".";
                struct path* dest = follow_symlink(path, inode, rest_pathname,
                                                   flags, symlink_depth);
                path_destroy_recursive(path);
                kfree(dup_pathname);
                return dest;
            }

            if (!(flags & O_NOFOLLOW_NOERROR)) {
                inode_unref(inode);
                path_destroy_recursive(path);
                kfree(dup_pathname);
                return ERR_PTR(-ELOOP);
            }
        }

        struct path* joined = path_join(path, inode, component);
        if (IS_ERR(joined)) {
            path_destroy_recursive(path);
            kfree(dup_pathname);
            return joined;
        }
        path = joined;
    }

    kfree(dup_pathname);
    return path;
}

struct path* vfs_resolve_path(const char* pathname, int flags) {
    mutex_lock(&current->fs->lock);
    struct path* ret = vfs_resolve_path_at(current->fs->cwd, pathname, flags);
    mutex_unlock(&current->fs->lock);
    return ret;
}

struct path* vfs_resolve_path_at(const struct path* base, const char* pathname,
                                 int flags) {
    return resolve_path_at(base, pathname, flags, 0);
}

static struct path* create_at(const struct path* base, const char* pathname,
                              mode_t mode, bool exclusive) {
    ASSERT(mode & S_IFMT);

    struct path* path = vfs_resolve_path_at(base, pathname, O_ALLOW_NOENT);
    if (IS_ERR(path))
        return ERR_CAST(path);

    if (path->inode) {
        if (exclusive) {
            path_destroy_recursive(path);
            return ERR_PTR(-EEXIST);
        }
        return path;
    }

    struct path* parent = path->parent;
    if (!S_ISDIR(parent->inode->mode)) {
        path_destroy_recursive(path);
        return ERR_PTR(-ENOTDIR);
    }

    inode_ref(parent->inode);
    struct inode* new_inode = mount_create_inode(parent->inode->mount, mode);
    if (IS_ERR(new_inode)) {
        path_destroy_recursive(path);
        return ERR_CAST(new_inode);
    }

    int rc = 0;
    for (;;) {
        inode_ref(parent->inode);
        inode_ref(new_inode);
        rc = inode_link(parent->inode, path->basename, new_inode);
        if (IS_OK(rc)) {
            path->inode = new_inode;
            break;
        }
        if (rc != -EEXIST || exclusive)
            break;
        // Another task is linking the same file. Look up the linked file.
        rc = 0;

        inode_ref(parent->inode);
        struct inode* inode = inode_lookup(parent->inode, path->basename);
        if (IS_OK(inode)) {
            inode_unref(new_inode);
            path->inode = inode;
            break;
        }
        if (PTR_ERR(inode) != -ENOENT) {
            inode_unref(new_inode);
            rc = PTR_ERR(inode);
            break;
        }
        // The file was unlinked before we could look it up. Retry linking it.
    }
    if (IS_ERR(rc)) {
        path_destroy_recursive(path);
        return ERR_PTR(rc);
    }

    return path;
}

struct file* vfs_open(const char* pathname, int flags, mode_t mode) {
    mutex_lock(&current->fs->lock);
    struct file* ret = vfs_open_at(current->fs->cwd, pathname, flags, mode);
    mutex_unlock(&current->fs->lock);
    return ret;
}

struct file* vfs_open_at(const struct path* base, const char* pathname,
                         int flags, mode_t mode) {
    struct path* path = (flags & O_CREAT)
                            ? create_at(base, pathname, mode, flags & O_EXCL)
                            : vfs_resolve_path_at(base, pathname, flags);
    if (IS_ERR(path))
        return ERR_CAST(path);

    struct inode* inode = path_into_inode(path);
    ASSERT(inode);
    return inode_open(inode, flags);
}

int vfs_stat(const char* pathname, struct kstat* buf, int flags) {
    mutex_lock(&current->fs->lock);
    int ret = vfs_stat_at(current->fs->cwd, pathname, buf, flags);
    mutex_unlock(&current->fs->lock);
    return ret;
}

int vfs_stat_at(const struct path* base, const char* pathname,
                struct kstat* buf, int flags) {
    struct path* path = vfs_resolve_path_at(base, pathname, flags);
    if (IS_ERR(path))
        return PTR_ERR(path);
    struct inode* inode = path_into_inode(path);
    ASSERT(inode);
    return inode_stat(inode, buf);
}

struct inode* vfs_create(const char* pathname, mode_t mode) {
    mutex_lock(&current->fs->lock);
    struct inode* ret = vfs_create_at(current->fs->cwd, pathname, mode);
    mutex_unlock(&current->fs->lock);
    return ret;
}

struct inode* vfs_create_at(const struct path* base, const char* pathname,
                            mode_t mode) {
    struct path* path = create_at(base, pathname, mode, true);
    if (IS_ERR(path))
        return ERR_CAST(path);
    return path_into_inode(path);
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
    ASSERT_OK(mount);
    root = mount->root;
    ASSERT(root);

    kprintf("vfs: populating root fs with initrd at P%#x - P%#x\n",
            initrd_mod->mod_start, initrd_mod->mod_end);
    initrd_populate_root_fs(initrd_mod->mod_start,
                            initrd_mod->mod_end - initrd_mod->mod_start);
}
