#include "private.h"
#include <common/string.h>
#include <common/tree.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/containers/vec.h>
#include <kernel/fs/file.h>
#include <kernel/fs/inode.h>
#include <kernel/fs/vfs.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/phys.h>
#include <kernel/panic.h>

static struct slab ramfs_inode_slab;
static struct slab ramfs_dentry_slab;

struct ramfs_inode {
    struct inode vfs_inode;
    struct tree children;
};

struct ramfs_dentry {
    char* name;
    struct inode* inode;
    struct tree_node tree_node; // Node in ramfs_inode->children
};

static void ramfs_dentry_destroy(struct ramfs_dentry* dentry) {
    kfree(dentry->name);
    inode_unref(dentry->inode);
    slab_free(&ramfs_dentry_slab, dentry);
}

static void ramfs_destroy(struct inode* vfs_inode) {
    struct ramfs_inode* inode =
        CONTAINER_OF(vfs_inode, struct ramfs_inode, vfs_inode);
    for (;;) {
        struct tree_node* tree_node = inode->children.root;
        if (!tree_node)
            break;
        tree_remove(&inode->children, tree_node);
        struct ramfs_dentry* dentry =
            CONTAINER_OF(tree_node, struct ramfs_dentry, tree_node);
        ramfs_dentry_destroy(dentry);
    }
    slab_free(&ramfs_inode_slab, inode);
}

static struct ramfs_dentry* find_dentry(struct ramfs_inode* parent,
                                        const char* name) {
    struct tree_node* tree_node = parent->children.root;
    while (tree_node) {
        struct ramfs_dentry* dentry =
            CONTAINER_OF(tree_node, struct ramfs_dentry, tree_node);
        int cmp = strcmp(name, dentry->name);
        if (cmp < 0)
            tree_node = tree_node->left;
        else if (cmp > 0)
            tree_node = tree_node->right;
        else
            return dentry;
    }
    return NULL;
}

static struct inode* ramfs_lookup(struct inode* vfs_parent, const char* name) {
    struct ramfs_inode* parent =
        CONTAINER_OF(vfs_parent, struct ramfs_inode, vfs_inode);

    SCOPED_LOCK(inode, vfs_parent);

    struct ramfs_dentry* dentry = find_dentry(parent, name);
    if (dentry)
        return inode_ref(dentry->inode);

    return ERR_PTR(-ENOENT);
}

static int ramfs_link(struct inode* vfs_parent, const char* name,
                      struct inode* vfs_child) {
    struct ramfs_inode* parent =
        CONTAINER_OF(vfs_parent, struct ramfs_inode, vfs_inode);

    SCOPED_LOCK(inode, vfs_parent);

    struct tree_node** new_tree_node = &parent->children.root;
    struct tree_node* parent_tree_node = NULL;
    while (*new_tree_node) {
        parent_tree_node = *new_tree_node;
        struct ramfs_dentry* dentry =
            CONTAINER_OF(parent_tree_node, struct ramfs_dentry, tree_node);
        int cmp = strcmp(name, dentry->name);
        if (cmp < 0)
            new_tree_node = &parent_tree_node->left;
        else if (cmp > 0)
            new_tree_node = &parent_tree_node->right;
        else
            return -EEXIST;
    }

    struct ramfs_dentry* dentry = ASSERT(slab_alloc(&ramfs_dentry_slab));
    if (IS_ERR(dentry))
        return PTR_ERR(dentry);
    *dentry = (struct ramfs_dentry){0};
    dentry->name = kstrdup(name);
    if (!dentry->name) {
        slab_free(&ramfs_dentry_slab, dentry);
        return -ENOMEM;
    }
    dentry->inode = inode_ref(vfs_child);

    *new_tree_node = &dentry->tree_node;
    tree_insert(&parent->children, parent_tree_node, *new_tree_node);

    return 0;
}

static int ramfs_unlink(struct inode* vfs_parent, const char* name) {
    struct ramfs_inode* parent =
        CONTAINER_OF(vfs_parent, struct ramfs_inode, vfs_inode);

    SCOPED_LOCK(inode, vfs_parent);

    struct ramfs_dentry* dentry = find_dentry(parent, name);
    if (dentry) {
        tree_remove(&parent->children, &dentry->tree_node);
        ramfs_dentry_destroy(dentry);
        return 0;
    }

    return -ENOENT;
}

static int ramfs_getdents(struct file* file, getdents_callback_fn callback,
                          void* ctx) {
    struct inode* vfs_inode = file->inode;
    struct ramfs_inode* inode =
        CONTAINER_OF(vfs_inode, struct ramfs_inode, vfs_inode);

    SCOPED_LOCK(file, file);
    SCOPED_LOCK(inode, vfs_inode);

    struct tree_node* tree_node = tree_first(&inode->children);
    if (!tree_node)
        return 0;

    for (uint64_t i = 0; i < file->offset; ++i) {
        tree_node = tree_next(tree_node);
        if (!tree_node)
            return 0;
    }

    for (; tree_node; tree_node = tree_next(tree_node)) {
        struct ramfs_dentry* child =
            CONTAINER_OF(tree_node, struct ramfs_dentry, tree_node);
        ASSERT_PTR(child->name);
        unsigned char type = mode_to_dirent_type(child->inode->mode);
        if (!callback(child->name, child->inode->ino, type, ctx))
            break;
        ++file->offset;
    }

    return 0;
}

// This is called only when populating the page cache.
// Since ramfs is empty when created, we can just fill the page with zeros.
static int ramfs_read(struct inode* inode, struct page* page,
                      size_t page_index) {
    (void)inode;
    (void)page_index;
    page_clear(page, 0, PAGE_SIZE);
    return 0;
}

// The page cache stores the actual data, so we don't need to do anything here.
static int ramfs_write(struct inode* inode, struct page* page,
                       size_t page_index) {
    (void)inode;
    (void)page;
    (void)page_index;
    return 0;
}

// Truncating is handled by invalidating the page cache, so nothing to do here.
static int ramfs_truncate(struct inode* inode, uint64_t length) {
    (void)inode;
    (void)length;
    return 0;
}

static const struct inode_ops dir_iops = {
    .destroy = ramfs_destroy,
    .lookup = ramfs_lookup,
    .link = ramfs_link,
    .unlink = ramfs_unlink,
};
static const struct file_ops dir_fops = {
    .getdents = ramfs_getdents,
};
static const struct inode_ops file_iops = {
    .destroy = ramfs_destroy,
    .read = ramfs_read,
    .write = ramfs_write,
    .truncate = ramfs_truncate,
};
static const struct file_ops file_fops = {0};

struct ramfs_mount {
    struct mount vfs_mount;
    _Atomic(ino_t) next_ino;
};

static struct inode* ramfs_create_inode(struct mount* vfs_mount, mode_t mode) {
    struct ramfs_mount* mount =
        CONTAINER_OF(vfs_mount, struct ramfs_mount, vfs_mount);

    struct ramfs_inode* inode = ASSERT(slab_alloc(&ramfs_inode_slab));
    if (IS_ERR(inode))
        return ERR_CAST(inode);
    *inode = (struct ramfs_inode){
        .vfs_inode = INODE_INIT,
    };

    struct inode* vfs_inode = &inode->vfs_inode;
    vfs_inode->ino = atomic_fetch_add(&mount->next_ino, 1);
    vfs_inode->iops = S_ISDIR(mode) ? &dir_iops : &file_iops;
    vfs_inode->fops = S_ISDIR(mode) ? &dir_fops : &file_fops;
    vfs_inode->mode = mode;
    return vfs_inode;
}

static struct mount* ramfs_mount(const char* source) {
    (void)source;

    struct ramfs_mount* mount = kmalloc(sizeof(struct ramfs_mount));
    if (!mount)
        return ERR_PTR(-ENOMEM);
    *mount = (struct ramfs_mount){
        .next_ino = 1,
    };

    struct mount* vfs_mount = &mount->vfs_mount;
    struct inode* root FREE(inode) =
        ASSERT(ramfs_create_inode(vfs_mount, S_IFDIR));
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

static struct mount* devtmpfs_singleton;

static struct mount* devtmpfs_mount(const char* source) {
    if (devtmpfs_singleton)
        return ASSERT_PTR(devtmpfs_singleton);
    return ramfs_mount(source);
}

int devtmpfs_mknod(const char* name, mode_t mode, dev_t dev) {
    struct mount* mount = ASSERT_PTR(devtmpfs_singleton);
    struct inode* root = ASSERT_PTR(mount->root);

    ASSERT(mode & S_IFMT);
    if (!(mode & ALLPERMS))
        mode |= 0600;

    struct inode* inode FREE(inode) = ASSERT(mount_create_inode(mount, mode));
    if (IS_ERR(inode))
        return PTR_ERR(inode);
    inode->rdev = dev;

    return inode_link(root, name, inode);
}

void ramfs_init(void) {
    SLAB_INIT_FOR_TYPE(&ramfs_inode_slab, "ramfs_inode", struct ramfs_inode);
    SLAB_INIT_FOR_TYPE(&ramfs_dentry_slab, "ramfs_dentry", struct ramfs_dentry);

    static struct file_system ramfs = {
        .name = "ramfs",
        .mount = ramfs_mount,
        .create_inode = ramfs_create_inode,
    };
    ASSERT_OK(file_system_register(&ramfs));

    // For now, tmpfs is just an alias of ramfs.
    static struct file_system tmpfs = {
        .name = "tmpfs",
        .mount = ramfs_mount,
        .create_inode = ramfs_create_inode,
    };
    ASSERT_OK(file_system_register(&tmpfs));

    static struct file_system devtmpfs = {
        .name = "devtmpfs",
        .mount = devtmpfs_mount,
        .create_inode = ramfs_create_inode,
    };
    devtmpfs_singleton = ASSERT_PTR(file_system_mount(&devtmpfs, "devtmpfs"));
    ASSERT_OK(file_system_register(&devtmpfs));
}
