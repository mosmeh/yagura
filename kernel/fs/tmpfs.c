#include "fs.h"
#include <common/string.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/containers/vec.h>
#include <kernel/device/device.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

static struct slab tmpfs_inode_slab;
static struct slab tmpfs_dentry_slab;

struct tmpfs_inode {
    struct inode vfs_inode;
    struct tmpfs_dentry* children;
};

struct tmpfs_dentry {
    char* name;
    struct inode* inode;
    struct tmpfs_dentry* next;
};

static void tmpf_dentry_destroy(struct tmpfs_dentry* dentry) {
    kfree(dentry->name);
    inode_unref(dentry->inode);
    slab_free(&tmpfs_dentry_slab, dentry);
}

static void tmpfs_destroy(struct inode* vfs_inode) {
    struct tmpfs_inode* inode =
        CONTAINER_OF(vfs_inode, struct tmpfs_inode, vfs_inode);
    for (struct tmpfs_dentry* child = inode->children; child;) {
        struct tmpfs_dentry* next = child->next;
        tmpf_dentry_destroy(child);
        child = next;
    }
    slab_free(&tmpfs_inode_slab, inode);
}

static struct inode* tmpfs_lookup(struct inode* vfs_parent, const char* name) {
    struct tmpfs_inode* parent =
        CONTAINER_OF(vfs_parent, struct tmpfs_inode, vfs_inode);

    inode_lock(vfs_parent);

    struct inode* inode = NULL;
    for (struct tmpfs_dentry* child = parent->children; child;
         child = child->next) {
        ASSERT(child->name);
        if (!strcmp(child->name, name)) {
            inode = inode_ref(child->inode);
            break;
        }
    }

    inode_unlock(vfs_parent);

    return inode ? inode : ERR_PTR(-ENOENT);
}

static int tmpfs_link(struct inode* vfs_parent, const char* name,
                      struct inode* vfs_child) {
    struct tmpfs_inode* parent =
        CONTAINER_OF(vfs_parent, struct tmpfs_inode, vfs_inode);

    int rc = 0;
    struct tmpfs_dentry* dentry = NULL;
    inode_lock(vfs_parent);

    struct tmpfs_dentry* prev = NULL;
    for (struct tmpfs_dentry* it = parent->children; it;) {
        ASSERT(it->name);
        if (!strcmp(it->name, name)) {
            rc = -EEXIST;
            goto fail;
        }
        prev = it;
        it = it->next;
    }

    dentry = slab_alloc(&tmpfs_dentry_slab);
    if (IS_ERR(dentry)) {
        rc = PTR_ERR(dentry);
        goto fail;
    }
    *dentry = (struct tmpfs_dentry){0};
    dentry->name = kstrdup(name);
    if (!dentry->name) {
        rc = -ENOMEM;
        goto fail;
    }
    dentry->inode = inode_ref(vfs_child);
    if (prev) {
        prev->next = dentry;
    } else {
        ASSERT(!parent->children);
        parent->children = dentry;
    }

    goto exit;

fail:
    slab_free(&tmpfs_dentry_slab, dentry);
exit:
    inode_unlock(vfs_parent);
    return rc;
}

static int tmpfs_unlink(struct inode* vfs_parent, const char* name) {
    struct tmpfs_inode* parent =
        CONTAINER_OF(vfs_parent, struct tmpfs_inode, vfs_inode);

    int rc = -ENOENT;
    inode_lock(vfs_parent);

    struct tmpfs_dentry* prev = NULL;
    struct tmpfs_dentry* dentry = parent->children;
    while (dentry) {
        ASSERT(dentry->name);
        if (!strcmp(dentry->name, name))
            break;
        prev = dentry;
        dentry = dentry->next;
    }
    if (dentry) {
        if (prev)
            prev->next = dentry->next;
        else
            parent->children = dentry->next;

        tmpf_dentry_destroy(dentry);
        rc = 0;
    }

    inode_unlock(vfs_parent);
    return rc;
}

static int tmpfs_getdents(struct file* file, getdents_callback_fn callback,
                          void* ctx) {
    struct inode* vfs_inode = file->inode;
    struct tmpfs_inode* inode =
        CONTAINER_OF(vfs_inode, struct tmpfs_inode, vfs_inode);

    inode_lock(vfs_inode);

    struct tmpfs_dentry* child = inode->children;
    if (!child)
        goto unlock_inode;

    mutex_lock(&file->lock);

    for (uint64_t i = 0; i < file->offset; ++i) {
        child = child->next;
        if (!child)
            goto unlock_file;
    }

    for (; child; child = child->next) {
        ASSERT(child->name);
        struct inode* inode = child->inode;
        unsigned char type = mode_to_dirent_type(inode->mode);
        if (!callback(child->name, inode->ino, type, ctx))
            break;
        ++file->offset;
    }

unlock_file:
    mutex_unlock(&file->lock);
unlock_inode:
    inode_unlock(vfs_inode);

    return 0;
}

// This is called only when populating the page cache.
// Since tmpfs is empty when created, we can just return no data.
static ssize_t tmpfs_pread(struct inode* inode, void* buffer, size_t count,
                           uint64_t offset) {
    (void)inode;
    (void)buffer;
    (void)count;
    (void)offset;
    return 0;
}

// The page cache stores the actual data, so we don't need to do anything here.
static ssize_t tmpfs_pwrite(struct inode* inode, const void* buffer,
                            size_t count, uint64_t offset) {
    (void)inode;
    (void)buffer;
    (void)offset;
    return count;
}

// Truncating is handled by invalidating the page cache, so nothing to do here.
static int tmpfs_truncate(struct inode* inode, uint64_t length) {
    (void)inode;
    (void)length;
    return 0;
}

static const struct inode_ops dir_iops = {
    .destroy = tmpfs_destroy,
    .lookup = tmpfs_lookup,
    .link = tmpfs_link,
    .unlink = tmpfs_unlink,
};
static const struct file_ops dir_fops = {
    .getdents = tmpfs_getdents,
};
static const struct inode_ops file_iops = {
    .destroy = tmpfs_destroy,
    .pread = tmpfs_pread,
    .pwrite = tmpfs_pwrite,
    .truncate = tmpfs_truncate,
};
static const struct file_ops file_fops = {0};

struct tmpfs_mount {
    struct mount vfs_mount;
    _Atomic(ino_t) next_ino;
};

static struct inode* tmpfs_create_inode(struct mount* vfs_mount, mode_t mode) {
    struct tmpfs_mount* mount =
        CONTAINER_OF(vfs_mount, struct tmpfs_mount, vfs_mount);

    struct tmpfs_inode* inode = slab_alloc(&tmpfs_inode_slab);
    if (IS_ERR(inode))
        return ERR_CAST(inode);
    *inode = (struct tmpfs_inode){
        .vfs_inode = INODE_INIT,
    };

    struct inode* vfs_inode = &inode->vfs_inode;
    vfs_inode->ino = atomic_fetch_add(&mount->next_ino, 1);
    vfs_inode->iops = S_ISDIR(mode) ? &dir_iops : &file_iops;
    vfs_inode->fops = S_ISDIR(mode) ? &dir_fops : &file_fops;
    vfs_inode->mode = mode;
    return vfs_inode;
}

static struct mount* tmpfs_mount(const char* source) {
    (void)source;

    struct tmpfs_mount* mount = kmalloc(sizeof(struct tmpfs_mount));
    if (!mount)
        return ERR_PTR(-ENOMEM);
    *mount = (struct tmpfs_mount){
        .next_ino = 1,
    };

    struct mount* vfs_mount = &mount->vfs_mount;
    struct inode* root FREE(inode) = tmpfs_create_inode(vfs_mount, S_IFDIR);
    if (IS_ERR(root)) {
        kfree(mount);
        return ERR_CAST(root);
    }
    int rc = mount_commit_inode(vfs_mount, root);
    if (IS_ERR(rc)) {
        kfree(mount);
        return ERR_PTR(rc);
    }
    mount_set_root(vfs_mount, root);

    return vfs_mount;
}

void tmpfs_init(void) {
    slab_init(&tmpfs_inode_slab, sizeof(struct tmpfs_inode));
    slab_init(&tmpfs_dentry_slab, sizeof(struct tmpfs_dentry));

    static const struct fs_ops fs_ops = {
        .mount = tmpfs_mount,
        .create_inode = tmpfs_create_inode,
    };
    static struct file_system fs = {
        .name = "tmpfs",
        .fs_ops = &fs_ops,
    };
    ASSERT_OK(file_system_register(&fs));
}
