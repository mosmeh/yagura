#include "private.h"
#include <common/string.h>
#include <kernel/containers/vec.h>
#include <kernel/device/device.h>
#include <kernel/fs/fs.h>
#include <kernel/panic.h>

struct proc_inode {
    struct inode vfs_inode;
    const struct proc_entry* entry; // NULL if a per-process directory
};

static struct slab proc_inode_slab;
static struct slab vec_slab;

static void proc_destroy(struct inode* vfs_inode) {
    struct proc_inode* inode =
        CONTAINER_OF(vfs_inode, struct proc_inode, vfs_inode);
    slab_free(&proc_inode_slab, inode);
}

static int proc_open(struct file* file) {
    struct vec* vec = slab_alloc(&vec_slab);
    if (!vec)
        return -ENOMEM;
    *vec = (struct vec){0};

    struct proc_inode* inode =
        CONTAINER_OF(file->inode, struct proc_inode, vfs_inode);
    const struct proc_entry* entry = inode->entry;
    int rc = entry->print(file, vec);
    if (IS_ERR(rc)) {
        vec_destroy(vec);
        slab_free(&vec_slab, vec);
        return rc;
    }

    file->private_data = vec;
    return 0;
}

static int proc_close(struct file* file) {
    struct vec* vec = file->private_data;
    vec_destroy(vec);
    slab_free(&vec_slab, vec);
    return 0;
}

static ssize_t proc_pread(struct file* file, void* buffer, size_t count,
                          uint64_t offset) {
    struct vec* vec = file->private_data;
    return vec_pread(vec, buffer, count, offset);
}

static const struct inode_ops root_iops = {
    .destroy = proc_destroy,
    .lookup = proc_root_lookup,
};
static const struct file_ops root_fops = {
    .getdents = proc_root_getdents,
};

static const struct inode_ops pid_iops = {
    .destroy = proc_destroy,
    .lookup = proc_pid_lookup,
};
static const struct file_ops pid_fops = {
    .getdents = proc_pid_getdents,
};

static const struct inode_ops entry_iops = {
    .destroy = proc_destroy,
};
static const struct file_ops entry_fops = {
    .open = proc_open,
    .close = proc_close,
    .pread = proc_pread,
};

static struct inode* alloc_inode(ino_t ino, struct proc_entry* entry) {
    struct proc_inode* node = slab_alloc(&proc_inode_slab);
    if (!node)
        return ERR_PTR(-ENOMEM);
    *node = (struct proc_inode){
        .vfs_inode = INODE_INIT,
        .entry = entry,
    };

    struct inode* inode = &node->vfs_inode;
    inode->ino = ino;
    if (ino == PROC_ROOT_INO) {
        inode->iops = &root_iops;
        inode->fops = &root_fops;
        inode->mode = S_IFDIR;
    } else if (entry) {
        inode->iops = &entry_iops;
        inode->fops = &entry_fops;
        inode->mode = entry->mode;
    } else {
        ASSERT(ino >= (1 << PROC_PID_INO_SHIFT));
        inode->iops = &pid_iops;
        inode->fops = &pid_fops;
        inode->mode = S_IFDIR;
    }

    return inode;
}

struct inode* proc_create_inode(struct mount* mount, ino_t ino,
                                struct proc_entry* entry) {
    mutex_lock(&mount->lock);

    struct inode* inode FREE(inode) = mount_lookup_inode(mount, ino);
    if (inode) {
        mutex_unlock(&mount->lock);
        return TAKE_PTR(inode);
    }

    inode = alloc_inode(ino, entry);
    if (IS_ERR(inode)) {
        mutex_unlock(&mount->lock);
        return inode;
    }

    int rc = mount_commit_inode(mount, inode);
    if (IS_ERR(rc)) {
        mutex_unlock(&mount->lock);
        return ERR_PTR(rc);
    }

    mutex_unlock(&mount->lock);
    return TAKE_PTR(inode);
}

static ino_t child_ino(ino_t parent_ino, size_t index) {
    return parent_ino + 1 + index;
}

struct inode* proc_lookup(struct inode* parent, const char* name,
                          struct proc_entry* entries, size_t num_entries) {
    struct proc_entry* entry = entries;
    for (size_t i = 0; i < num_entries; ++i) {
        if (!strcmp(entry->name, name)) {
            ino_t ino = child_ino(parent->ino, i);
            return proc_create_inode(parent->mount, ino, entry);
        }
        ++entry;
    }
    return ERR_PTR(-ENOENT);
}

int proc_getdents(struct file* file, getdents_callback_fn callback, void* ctx,
                  const struct proc_entry* entries, size_t num_entries) {
    mutex_lock(&file->lock);
    ino_t parent_ino = file->inode->ino;
    for (size_t i = file->offset; i < num_entries; ++i) {
        const struct proc_entry* entry = &entries[i];
        ino_t ino = child_ino(parent_ino, i);
        if (!callback(entry->name, ino, mode_to_dirent_type(entry->mode), ctx))
            break;
        ++file->offset;
    }
    mutex_unlock(&file->lock);
    return 0;
}

static struct mount* proc_mount(const char* source) {
    (void)source;

    struct mount* mount FREE(kfree) = kmalloc(sizeof(struct mount));
    if (!mount)
        return ERR_PTR(-ENOMEM);
    *mount = (struct mount){0};

    struct inode* root FREE(inode) =
        proc_create_inode(mount, PROC_ROOT_INO, NULL);
    if (IS_ERR(root))
        return ERR_CAST(root);
    mount_set_root(mount, root);

    return TAKE_PTR(mount);
}

void proc_init(void) {
    slab_init(&proc_inode_slab, sizeof(struct proc_inode));
    slab_init(&vec_slab, sizeof(struct vec));

    static const struct fs_ops fs_ops = {
        .mount = proc_mount,
    };
    static struct file_system fs = {
        .name = "proc",
        .fs_ops = &fs_ops,
    };
    ASSERT_OK(file_system_register(&fs));
}
