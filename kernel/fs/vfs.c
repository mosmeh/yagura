#include "fs.h"
#include <common/string.h>
#include <kernel/api/fcntl.h>
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
    ASSERT_OK(vfs_mount(ROOT_DIR, tmpfs_create_root()));
}

void vfs_populate_root_fs(const multiboot_module_t* initrd_mod) {
    kprintf("vfs: populating root fs with initrd at P0x%x - P0x%x\n",
            initrd_mod->mod_start, initrd_mod->mod_end);
    initrd_populate_root_fs(initrd_mod->mod_start,
                            initrd_mod->mod_end - initrd_mod->mod_start);
}

struct inode* vfs_get_root(void) {
    ASSERT(root);
    inode_ref(root);
    return root;
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

int vfs_mount(const char* path, struct inode* fs_root) {
    if (path[0] == PATH_SEPARATOR && path[1] == '\0') {
        root = fs_root;
        return 0;
    }

    struct inode* inode = vfs_resolve_path(path, NULL, NULL);
    if (IS_ERR(inode))
        return PTR_ERR(inode);

    return mount_at(inode, fs_root);
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

typedef struct list_node {
    char* value;
    struct list_node* next;
} list_node;

static void list_destroy(list_node** list) {
    list_node* it = *list;
    while (it) {
        list_node* next = it->next;
        kfree(it->value);
        kfree(it);
        it = next;
    }
    *list = NULL;
}

static int list_push(list_node** list, const char* value) {
    list_node* node = kmalloc(sizeof(list_node));
    if (!node)
        return -ENOMEM;
    node->value = kstrdup(value);
    if (!node->value) {
        kfree(node);
        return -ENOMEM;
    }

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
    if (it) {
        kfree(it->value);
        kfree(it);
    }
}

static bool is_absolute_path(const char* path) {
    return path[0] == PATH_SEPARATOR;
}

static int create_path_component_list(const char* pathname,
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

    if (!is_absolute_path(pathname)) {
        char* dup_cwd = kstrdup(current->cwd_path);
        if (!dup_cwd)
            return -ENOMEM;

        char* saved_ptr;
        for (const char* component =
                 strtok_r(dup_cwd, PATH_SEPARATOR_STR, &saved_ptr);
             component;
             component = strtok_r(NULL, PATH_SEPARATOR_STR, &saved_ptr)) {
            int rc = list_push(&list, component);
            if (IS_ERR(rc)) {
                list_destroy(&list);
                kfree(dup_cwd);
                return rc;
            }
            ++num_components;
        }

        kfree(dup_cwd);
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
        if (IS_ERR(rc)) {
            list_destroy(&list);
            kfree(dup_path);
            return rc;
        }
        ++num_components;
    }

    kfree(dup_path);

    if (out_list)
        *out_list = list;
    else
        list_destroy(&list);
    if (out_num_components)
        *out_num_components = num_components;

    return 0;
}

struct inode* vfs_resolve_path(const char* pathname, struct inode** out_parent,
                               char** out_basename) {
    list_node* component_list = NULL;
    size_t num_components = 0;
    int rc =
        create_path_component_list(pathname, &component_list, &num_components);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    if (num_components == 0)
        return vfs_get_root();

    struct inode* parent = vfs_get_root();
    size_t i = 0;
    for (list_node* node = component_list; node; node = node->next) {
        const char* component = node->value;
        if (i == num_components - 1) { // last component
            if (out_basename) {
                char* dup_basename = kstrdup(component);
                if (!dup_basename) {
                    inode_unref(parent);
                    list_destroy(&component_list);
                    return ERR_PTR(-ENOMEM);
                }
                *out_basename = dup_basename;
            }
            if (out_parent) {
                inode_ref(parent);
                *out_parent = parent;
            }
        }

        struct inode* child = inode_lookup_child(parent, component);
        if (IS_ERR(child)) {
            list_destroy(&component_list);
            return child;
        }

        parent = resolve_mounts(child);
        ++i;
    }

    list_destroy(&component_list);
    return parent;
}

char* vfs_canonicalize_path(const char* pathname) {
    list_node* component_list = NULL;
    size_t num_components = 0;
    int rc =
        create_path_component_list(pathname, &component_list, &num_components);
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
    if (!canonicalized) {
        list_destroy(&component_list);
        return ERR_PTR(-ENOMEM);
    }
    size_t idx = 0;
    for (list_node* node = component_list; node; node = node->next) {
        canonicalized[idx++] = PATH_SEPARATOR;
        size_t len = strlen(node->value);
        strncpy(canonicalized + idx, node->value, len);
        idx += len;
    }
    canonicalized[idx] = '\0';

    list_destroy(&component_list);
    return canonicalized;
}

static struct inode* create_inode(const char* pathname, mode_t mode,
                                  bool exclusive) {
    struct inode* parent = NULL;
    char* basename = NULL;
    struct inode* inode = vfs_resolve_path(pathname, &parent, &basename);
    if (IS_OK(inode)) {
        inode_unref(parent);
        kfree(basename);
        if (exclusive) {
            inode_unref(inode);
            return ERR_PTR(-EEXIST);
        }
        return inode;
    }
    if (PTR_ERR(inode) != -ENOENT || !parent) {
        inode_unref(parent);
        kfree(basename);
        return inode;
    }

    // retry if another process is modifying the inode at the same time
    for (;;) {
        inode_ref(parent);
        inode = inode_create_child(parent, basename, mode);
        if (IS_OK(inode) || PTR_ERR(inode) != -EEXIST || exclusive)
            break;

        inode_ref(parent);
        inode = inode_lookup_child(parent, basename);
        if (IS_OK(inode) || PTR_ERR(inode) != -ENOENT)
            break;
    }

    inode_unref(parent);
    kfree(basename);
    return inode;
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

file_description* vfs_open(const char* pathname, int flags, mode_t mode) {
    struct inode* inode = (flags & O_CREAT)
                              ? create_inode(pathname, mode, flags & O_EXCL)
                              : vfs_resolve_path(pathname, NULL, NULL);
    if (IS_ERR(inode))
        return ERR_CAST(inode);

    inode = resolve_special_file(inode);
    if (IS_ERR(inode))
        return ERR_CAST(inode);

    return inode_open(inode, flags, mode);
}

int vfs_stat(const char* pathname, struct stat* buf) {
    struct inode* inode = vfs_resolve_path(pathname, NULL, NULL);
    if (IS_ERR(inode))
        return PTR_ERR(inode);
    return inode_stat(inode, buf);
}

struct inode* vfs_create(const char* pathname, mode_t mode) {
    return create_inode(pathname, mode, true);
}
