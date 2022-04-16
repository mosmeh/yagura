#include "fs.h"
#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stat.h>
#include <kernel/api/sysmacros.h>
#include <kernel/kmalloc.h>
#include <kernel/kprintf.h>
#include <kernel/panic.h>
#include <kernel/process.h>
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
        for (;;) {
            if (it->file->device_id == device_file->device_id)
                return -EEXIST;
            if (!it->next)
                break;
            it = it->next;
        }
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

typedef struct list_node {
    const char* value;
    struct list_node* next;
} list_node;

static int list_push(list_node** list, const char* value) {
    list_node* node = kmalloc(sizeof(list_node));
    if (!node)
        return -ENOMEM;
    node->value = value;
    node->next = NULL;
    if (*list) {
        list_node* it = *list;
        while (it->next)
            it = it->next;
        it->next = node;
    } else {
        *list = node;
    }
    return 0;
}

static void list_pop(list_node** list) {
    list_node* prev = NULL;
    list_node* it = *list;
    while (it) {
        if (!it->next)
            break;
        prev = it;
        it = it->next;
    }
    if (prev)
        prev->next = NULL;
    else
        *list = NULL;
}

static int create_path_component_list(const char* pathname,
                                      const char* parent_path,
                                      list_node** out_list,
                                      size_t* out_num_components) {
    if (pathname[0] == PATH_SEPARATOR && pathname[1] == '\0') {
        if (out_list)
            *out_list = NULL;
        if (out_num_components)
            *out_num_components = 0;
        return 0;
    }

    list_node* list = NULL;
    size_t num_components = 0;

    if (!is_absolute_path(pathname) && parent_path) {
        char* dup_parent_path = kstrdup(parent_path);
        if (!dup_parent_path)
            return -ENOMEM;

        char* saved_ptr;
        for (const char* component =
                 strtok_r(dup_parent_path, PATH_SEPARATOR_STR, &saved_ptr);
             component;
             component = strtok_r(NULL, PATH_SEPARATOR_STR, &saved_ptr)) {
            int rc = list_push(&list, component);
            if (IS_ERR(rc))
                return rc;
            ++num_components;
        }
    }

    char* dup_path = kstrdup(pathname);
    if (!dup_path)
        return -ENOMEM;

    char* saved_ptr;
    for (const char* component =
             strtok_r(dup_path, PATH_SEPARATOR_STR, &saved_ptr);
         component;
         component = strtok_r(NULL, PATH_SEPARATOR_STR, &saved_ptr)) {
        if (component[0] == '.' && component[1] == '\0')
            continue;
        if (!strcmp(component, "..")) {
            if (num_components > 0) { // "/.." becomes "/"
                list_pop(&list);
                --num_components;
            }
            continue;
        }
        int rc = list_push(&list, component);
        if (IS_ERR(rc))
            return rc;
        ++num_components;
    }

    if (out_list)
        *out_list = list;
    if (out_num_components)
        *out_num_components = num_components;

    return 0;
}

struct file* vfs_resolve_path(const char* pathname, const char* parent_path,
                              struct file** out_parent,
                              const char** out_basename) {
    ASSERT(root);

    list_node* component_list = NULL;
    size_t num_components = 0;
    int rc = create_path_component_list(pathname, parent_path, &component_list,
                                        &num_components);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    if (num_components == 0)
        return root;

    struct file* parent = root;
    size_t i = 0;
    for (list_node* node = component_list; node; node = node->next) {
        const char* component = node->value;
        if (i == num_components - 1) { // last component
            if (out_parent)
                *out_parent = parent;
            if (out_basename)
                *out_basename = component;
        }

        struct file* child = fs_lookup(parent, component);
        if (IS_ERR(child))
            return child;

        struct file* guest = get_mounted_guest(child);
        if (guest)
            child = guest;

        parent = child;
        ++i;
    }

    return parent;
}

char* vfs_canonicalize_path(const char* pathname, const char* parent_path) {
    list_node* component_list = NULL;
    size_t num_components = 0;
    int rc = create_path_component_list(pathname, parent_path, &component_list,
                                        &num_components);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    if (num_components == 0) {
        char* canonicalized = kstrdup(ROOT_DIR);
        if (!canonicalized)
            return ERR_PTR(-ENOMEM);
        return canonicalized;
    }

    size_t len = 0;
    for (list_node* node = component_list; node; node = node->next)
        len += strlen(node->value) + 1;

    char* canonicalized = kmalloc(len + 1);
    if (!canonicalized)
        return ERR_PTR(-ENOMEM);
    size_t idx = 0;
    for (list_node* node = component_list; node; node = node->next) {
        canonicalized[idx++] = PATH_SEPARATOR;
        strcpy(canonicalized + idx, node->value);
        idx += strlen(node->value);
    }
    canonicalized[idx] = '\0';

    return canonicalized;
}

file_description* vfs_open(const char* pathname, int flags, mode_t mode) {
    struct file* parent = NULL;
    const char* basename = NULL;
    struct file* file =
        vfs_resolve_path(pathname, current->cwd, &parent, &basename);
    if (IS_OK(file) && (flags & O_EXCL))
        return ERR_PTR(-EEXIST);
    if (IS_ERR(file)) {
        if ((flags & O_CREAT) && PTR_ERR(file) == -ENOENT && parent)
            file = fs_create_child(parent, basename, mode);
        else
            return ERR_CAST(file);
    }

    if (S_ISBLK(file->mode) || S_ISCHR(file->mode)) {
        struct file* device_file = get_device(file->device_id);
        if (!device_file)
            return ERR_PTR(-ENODEV);
        file = device_file;
    }

    int rc = fs_open(file, flags, mode);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    file_description* desc = kmalloc(sizeof(file_description));
    if (!desc)
        return ERR_PTR(-ENOMEM);
    desc->file = file;
    desc->offset = 0;
    desc->flags = flags;
    return desc;
}

struct file* vfs_create(const char* pathname, mode_t mode) {
    struct file* parent = NULL;
    const char* basename = NULL;
    struct file* file =
        vfs_resolve_path(pathname, current->cwd, &parent, &basename);
    if (IS_OK(file))
        return ERR_PTR(-EEXIST);
    if (PTR_ERR(file) != -ENOENT || !parent)
        return file;
    return fs_create_child(parent, basename, mode);
}
