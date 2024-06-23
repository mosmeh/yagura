#include "fs.h"
#include "path.h"
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/kprintf.h>
#include <kernel/lock.h>
#include <kernel/memory/memory.h>
#include <kernel/multiboot.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <string.h>

void initrd_populate_root_fs(uintptr_t paddr, size_t size);

static struct inode* root;

void vfs_init(void) {
    kprintf("vfs: mounting root filesystem\n");
    root = tmpfs_create_root();
}

void vfs_populate_root_fs(const multiboot_module_t* initrd_mod) {
    kprintf("vfs: populating root fs with initrd at P0x%x - P0x%x\n",
            initrd_mod->mod_start, initrd_mod->mod_end);
    initrd_populate_root_fs(initrd_mod->mod_start,
                            initrd_mod->mod_end - initrd_mod->mod_start);
}

struct path* vfs_get_root(void) {
    ASSERT(root);
    struct path* path = kmalloc(sizeof(struct path));
    if (!path)
        return ERR_PTR(-ENOMEM);
    *path = (struct path){.inode = root};
    inode_ref(root);
    return path;
}

typedef struct mount_point {
    struct inode* host;
    struct inode* guest;
    struct mount_point* next;
} mount_point;

static mount_point* mount_points;
static mutex mount_lock;

static int mount_at(struct inode* host, struct inode* guest) {
    if (!S_ISDIR(host->mode)) {
        inode_unref(host);
        inode_unref(guest);
        return -ENOTDIR;
    }
    mount_point* mp = kmalloc(sizeof(mount_point));
    if (!mp) {
        inode_unref(host);
        inode_unref(guest);
        return -ENOMEM;
    }
    mp->host = host;
    mp->guest = guest;
    mutex_lock(&mount_lock);
    mp->next = mount_points;
    mount_points = mp;
    mutex_unlock(&mount_lock);
    return 0;
}

static struct inode* resolve_mounts(struct inode* host) {
    struct inode* needle = host;
    mutex_lock(&mount_lock);
    for (;;) {
        mount_point* it = mount_points;
        while (it) {
            if (it->host == needle)
                break;
            it = it->next;
        }
        if (!it)
            break;
        needle = it->guest;
    }
    mutex_unlock(&mount_lock);
    if (needle != host)
        inode_ref(needle);
    return needle;
}

int vfs_mount(const char* pathname, struct inode* fs_root) {
    return vfs_mount_at(current->cwd, pathname, fs_root);
}

int vfs_mount_at(const struct path* base, const char* pathname,
                 struct inode* fs_root) {
    struct path* path = vfs_resolve_path_at(base, pathname, 0);
    if (IS_ERR(path))
        return PTR_ERR(path);

    return mount_at(path_into_inode(path), fs_root);
}

typedef struct device {
    struct inode* inode;
    struct device* next;
} device;

static device* devices;

int vfs_register_device(struct inode* inode) {
    device** dest = &devices;
    if (devices) {
        device* it = devices;
        for (;;) {
            if (it->inode->rdev == inode->rdev) {
                inode_unref(inode);
                return -EEXIST;
            }
            if (!it->next)
                break;
            it = it->next;
        }
        dest = &it->next;
    }
    device* dev = kmalloc(sizeof(device));
    if (!dev) {
        inode_unref(inode);
        return -ENOMEM;
    }
    dev->inode = inode;
    dev->next = NULL;
    *dest = dev;
    kprintf("vfs: registered device %u,%u\n", major(inode->rdev),
            minor(inode->rdev));
    return 0;
}

struct inode* vfs_get_device(dev_t id) {
    device* it = devices;
    while (it) {
        if (it->inode->rdev == id) {
            inode_ref(it->inode);
            return it->inode;
        }
        it = it->next;
    }
    return NULL;
}

dev_t vfs_generate_unnamed_device_number(void) {
    static int next_id = 1;
    int id = next_id++;
    return makedev(0, id);
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

    file_description* desc = inode_open(inode, O_RDONLY, 0);
    if (IS_ERR(desc))
        return ERR_CAST(desc);

    char target[SYMLINK_MAX];
    size_t target_len = 0;
    while (target_len < SYMLINK_MAX) {
        ssize_t nread = file_description_read(desc, target + target_len,
                                              SYMLINK_MAX - target_len);
        if (IS_ERR(nread)) {
            file_description_close(desc);
            return ERR_PTR(nread);
        }
        if (nread == 0)
            break;
        target_len += nread;
    }
    file_description_close(desc);

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
        struct inode* inode = inode_lookup_child(path->inode, component);

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
    return vfs_resolve_path_at(current->cwd, pathname, flags);
}

struct path* vfs_resolve_path_at(const struct path* base, const char* pathname,
                                 int flags) {
    return resolve_path_at(base, pathname, flags, 0);
}

static struct inode* resolve_special_file(struct inode* inode) {
    if (S_ISBLK(inode->mode) || S_ISCHR(inode->mode)) {
        struct inode* device = vfs_get_device(inode->rdev);
        inode_unref(inode);
        if (!device)
            return ERR_PTR(-ENODEV);
        return device;
    }

    if (S_ISFIFO(inode->mode)) {
        if (inode->fifo) {
            struct inode* fifo = inode->fifo;
            inode_ref(fifo);
            inode_unref(inode);
            return fifo;
        }

        struct inode* new_fifo = fifo_create();
        if (IS_ERR(new_fifo))
            return ERR_CAST(new_fifo);
        new_fifo->dev = inode->dev; // Signal that this fifo is bound to a file
        inode_ref(new_fifo);

        struct inode* expected = NULL;
        if (atomic_compare_exchange_strong(&inode->fifo, &expected, new_fifo)) {
            inode_unref(inode);
            return new_fifo;
        }
        inode_ref(expected);
        inode_unref(new_fifo);
        return expected;
    }

    return inode;
}

static struct path* create_at(const struct path* base, const char* pathname,
                              mode_t mode, bool exclusive) {
    struct path* path = vfs_resolve_path_at(base, pathname, O_ALLOW_NOENT);
    if (IS_ERR(path))
        return ERR_CAST(path);

    if (exclusive && path->inode) {
        path_destroy_recursive(path);
        return ERR_PTR(-EEXIST);
    }

    struct inode* inode = NULL;
    for (;;) {
        inode_ref(path->parent->inode);
        inode = inode_create_child(path->parent->inode, path->basename, mode);
        if (IS_OK(inode) || PTR_ERR(inode) != -EEXIST || exclusive)
            break;
        // Another process is creating the same file. Look up the created file.

        inode_ref(path->parent->inode);
        inode = inode_lookup_child(path->parent->inode, path->basename);
        if (IS_OK(inode) || PTR_ERR(inode) != -ENOENT)
            break;
        // The file was removed before we could look it up. Retry creating it.
    }

    path->inode = inode;
    return path;
}

file_description* vfs_open(const char* pathname, int flags, mode_t mode) {
    return vfs_open_at(current->cwd, pathname, flags, mode);
}

file_description* vfs_open_at(const struct path* base, const char* pathname,
                              int flags, mode_t mode) {
    struct path* path = (flags & O_CREAT)
                            ? create_at(base, pathname, mode, flags & O_EXCL)
                            : vfs_resolve_path_at(base, pathname, flags);
    if (IS_ERR(path))
        return ERR_CAST(path);

    struct inode* inode = path_into_inode(path);
    ASSERT(inode);

    inode = resolve_special_file(inode);
    if (IS_ERR(inode))
        return ERR_CAST(inode);

    return inode_open(inode, flags, mode);
}

int vfs_stat(const char* pathname, struct stat* buf, int flags) {
    return vfs_stat_at(current->cwd, pathname, buf, flags);
}

int vfs_stat_at(const struct path* base, const char* pathname, struct stat* buf,
                int flags) {
    struct path* path = vfs_resolve_path_at(base, pathname, flags);
    if (IS_ERR(path))
        return PTR_ERR(path);
    struct inode* inode = path_into_inode(path);
    ASSERT(inode);
    return inode_stat(inode, buf);
}

struct inode* vfs_create(const char* pathname, mode_t mode) {
    return vfs_create_at(current->cwd, pathname, mode);
}

struct inode* vfs_create_at(const struct path* base, const char* pathname,
                            mode_t mode) {
    struct path* path = create_at(base, pathname, mode, true);
    if (IS_ERR(path))
        return ERR_CAST(path);
    return path_into_inode(path);
}
