#include "fs.h"
#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/sysmacros.h>
#include <kernel/kmalloc.h>
#include <kernel/kprintf.h>
#include <kernel/panic.h>
#include <stdbool.h>
#include <string.h>

typedef struct mount_point {
    struct file* host;
    struct file* guest;
    struct mount_point* next;
} mount_point;

typedef struct device {
    struct file* file;
    struct device* next;
} device;

static struct file* root;
static mount_point* mount_points;
static device* devices;

static int mount_at(struct file* host, struct file* guest) {
    mount_point* mp = kmalloc(sizeof(mount_point));
    if (!mp)
        return -ENOMEM;
    mp->host = host;
    mp->guest = guest;
    mp->next = NULL;
    if (mount_points) {
        mount_point* it = mount_points;
        while (it->next)
            it = it->next;
        it->next = mp;
    } else {
        mount_points = mp;
    }
    return 0;
}

static struct file* get_mounted_guest(const struct file* host) {
    mount_point* it = mount_points;
    while (it) {
        if (it->host == host)
            return it->guest;
        it = it->next;
    }
    return NULL;
}

static bool is_absolute_path(const char* path) {
    return path[0] == PATH_SEPARATOR;
}

int vfs_mount(const char* path, struct file* root_file) {
    ASSERT(is_absolute_path(path));

    if (path[0] == PATH_SEPARATOR && path[1] == '\0') {
        root = root_file;
        kprintf("Mounted \"%s\" at /\n", root_file->name);
        return 0;
    }
    ASSERT(root);

    char* dup_path = kstrdup(path);
    ASSERT(dup_path);

    struct file* parent = root;
    char* saved_ptr;
    for (const char* component =
             strtok_r(dup_path, PATH_SEPARATOR_STR, &saved_ptr);
         component;
         component = strtok_r(NULL, PATH_SEPARATOR_STR, &saved_ptr)) {
        struct file* child = fs_lookup(parent, component);
        if (IS_ERR(child))
            return PTR_ERR(child);
        parent = child;
    }
    int rc = mount_at(parent, root_file);
    if (IS_ERR(rc))
        return rc;

    kprintf("Mounted \"%s\" at %s\n", root_file->name, path);
    return 0;
}

int vfs_register_device(struct file* device_file) {
    device* dev = kmalloc(sizeof(device));
    if (!dev)
        return -ENOMEM;
    dev->file = device_file;
    dev->next = NULL;
    if (devices) {
        device* it = devices;
        while (it->next)
            it = it->next;
        it->next = dev;
    } else {
        devices = dev;
    }
    kprintf("Registered device \"%s\" (%d:%d)\n", device_file->name,
            major(device_file->device_id), minor(device_file->device_id));
    return 0;
}

static struct file* get_device(dev_t id) {
    device* it = devices;
    while (it) {
        if (it->file->device_id == id)
            return it->file;
        it = it->next;
    }
    return NULL;
}

static struct file* get_or_create_file(const char* pathname, int flags,
                                       mode_t mode) {
    ASSERT(root);

    if (!is_absolute_path(pathname))
        return ERR_PTR(-ENOTSUP);

    size_t path_len = strlen(pathname);
    if (path_len == 1)
        return root;

    char* dup_path = kstrdup(pathname);
    if (!dup_path)
        return ERR_PTR(-ENOMEM);

    struct file* parent = root;
    char* saved_ptr;
    for (const char* component =
             strtok_r(dup_path, PATH_SEPARATOR_STR, &saved_ptr);
         component;
         component = strtok_r(NULL, PATH_SEPARATOR_STR, &saved_ptr)) {
        struct file* child = fs_lookup(parent, component);
        if (IS_ERR(child)) {
            if ((PTR_ERR(child) == -ENOENT) && (flags & O_CREAT) &&
                component + strlen(component) + 1 >= dup_path + path_len) {
                parent = fs_create_child(parent, component, mode);
                goto found_or_created;
            }
            return child;
        }

        struct file* guest = get_mounted_guest(child);
        if (guest)
            child = guest;

        parent = child;
    }

    if (flags & O_EXCL)
        return ERR_PTR(-EEXIST);

found_or_created:
    ASSERT(parent);
    struct file* file = parent;
    struct file* device_file = get_device(file->device_id);
    if (device_file)
        file = device_file;

    int rc = fs_open(file, flags, mode);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    return file;
}

file_description* vfs_open(const char* pathname, int flags, mode_t mode) {
    struct file* file = get_or_create_file(pathname, flags, mode);
    if (IS_ERR(file))
        return ERR_CAST(file);

    file_description* desc = kmalloc(sizeof(file_description));
    if (!desc)
        return ERR_PTR(-ENOMEM);
    desc->file = file;
    desc->offset = 0;
    desc->flags = flags;
    return desc;
}

struct file* vfs_create(const char* pathname, mode_t mode) {
    return get_or_create_file(pathname, O_CREAT | O_EXCL, mode);
}
