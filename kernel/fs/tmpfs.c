#include <common/string.h>
#include <common/tree.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/containers/vec.h>
#include <kernel/device/device.h>
#include <kernel/fs/file.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/phys.h>
#include <kernel/panic.h>

static struct slab tmpfs_inode_slab;
static struct slab tmpfs_dentry_slab;

struct tmpfs_inode {
    struct inode vfs_inode;
    struct tree children;
};

struct tmpfs_dentry {
    char* name;
    struct inode* inode;
    struct tree_node tree_node; // Node in tmpfs_inode->children
};

static void tmpfs_dentry_destroy(struct tmpfs_dentry* dentry) {
    kfree(dentry->name);
    inode_unref(dentry->inode);
    slab_free(&tmpfs_dentry_slab, dentry);
}

static void tmpfs_destroy(struct inode* vfs_inode) {
    struct tmpfs_inode* inode =
        CONTAINER_OF(vfs_inode, struct tmpfs_inode, vfs_inode);
    for (;;) {
        struct tree_node* tree_node = inode->children.root;
        if (!tree_node)
            break;
        tree_remove(&inode->children, tree_node);
        struct tmpfs_dentry* dentry =
            CONTAINER_OF(tree_node, struct tmpfs_dentry, tree_node);
        tmpfs_dentry_destroy(dentry);
    }
    slab_free(&tmpfs_inode_slab, inode);
}

static struct tmpfs_dentry* find_dentry(struct tmpfs_inode* parent,
                                        const char* name) {
    struct tree_node* tree_node = parent->children.root;
    while (tree_node) {
        struct tmpfs_dentry* dentry =
            CONTAINER_OF(tree_node, struct tmpfs_dentry, tree_node);
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

static struct inode* tmpfs_lookup(struct inode* vfs_parent, const char* name) {
    struct tmpfs_inode* parent =
        CONTAINER_OF(vfs_parent, struct tmpfs_inode, vfs_inode);

    SCOPED_LOCK(inode, vfs_parent);

    struct tmpfs_dentry* dentry = find_dentry(parent, name);
    if (dentry)
        return inode_ref(dentry->inode);

    return ERR_PTR(-ENOENT);
}

static int tmpfs_link(struct inode* vfs_parent, const char* name,
                      struct inode* vfs_child) {
    struct tmpfs_inode* parent =
        CONTAINER_OF(vfs_parent, struct tmpfs_inode, vfs_inode);

    SCOPED_LOCK(inode, vfs_parent);

    struct tree_node** new_tree_node = &parent->children.root;
    struct tree_node* parent_tree_node = NULL;
    while (*new_tree_node) {
        parent_tree_node = *new_tree_node;
        struct tmpfs_dentry* dentry =
            CONTAINER_OF(parent_tree_node, struct tmpfs_dentry, tree_node);
        int cmp = strcmp(name, dentry->name);
        if (cmp < 0)
            new_tree_node = &parent_tree_node->left;
        else if (cmp > 0)
            new_tree_node = &parent_tree_node->right;
        else
            return -EEXIST;
    }

    struct tmpfs_dentry* dentry = slab_alloc(&tmpfs_dentry_slab);
    if (IS_ERR(ASSERT(dentry)))
        return PTR_ERR(dentry);
    *dentry = (struct tmpfs_dentry){0};
    dentry->name = kstrdup(name);
    if (!dentry->name) {
        slab_free(&tmpfs_dentry_slab, dentry);
        return -ENOMEM;
    }
    dentry->inode = inode_ref(vfs_child);

    *new_tree_node = &dentry->tree_node;
    tree_insert(&parent->children, parent_tree_node, *new_tree_node);

    return 0;
}

static int tmpfs_unlink(struct inode* vfs_parent, const char* name) {
    struct tmpfs_inode* parent =
        CONTAINER_OF(vfs_parent, struct tmpfs_inode, vfs_inode);

    SCOPED_LOCK(inode, vfs_parent);

    struct tmpfs_dentry* dentry = find_dentry(parent, name);
    if (dentry) {
        tree_remove(&parent->children, &dentry->tree_node);
        tmpfs_dentry_destroy(dentry);
        return 0;
    }

    return -ENOENT;
}

static int tmpfs_getdents(struct file* file, getdents_callback_fn callback,
                          void* ctx) {
    struct inode* vfs_inode = file->inode;
    struct tmpfs_inode* inode =
        CONTAINER_OF(vfs_inode, struct tmpfs_inode, vfs_inode);

    SCOPED_LOCK(inode, vfs_inode);

    struct tree_node* tree_node = tree_first(&inode->children);
    if (!tree_node)
        return 0;

    SCOPED_LOCK(file, file);

    for (uint64_t i = 0; i < file->offset; ++i) {
        tree_node = tree_next(tree_node);
        if (!tree_node)
            return 0;
    }

    for (; tree_node; tree_node = tree_next(tree_node)) {
        struct tmpfs_dentry* child =
            CONTAINER_OF(tree_node, struct tmpfs_dentry, tree_node);
        ASSERT(child->name);
        struct inode* inode = child->inode;
        unsigned char type = mode_to_dirent_type(inode->mode);
        if (!callback(child->name, inode->ino, type, ctx))
            break;
        ++file->offset;
    }

    return 0;
}

// This is called only when populating the page cache.
// Since tmpfs is empty when created, we can just return no data.
static int tmpfs_read(struct inode* inode, struct page* page,
                      size_t page_index) {
    (void)inode;
    (void)page_index;
    page_fill(page, 0, 0, PAGE_SIZE);
    return 0;
}

// The page cache stores the actual data, so we don't need to do anything here.
static int tmpfs_write(struct inode* inode, struct page* page,
                       size_t page_index) {
    (void)inode;
    (void)page;
    (void)page_index;
    return 0;
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
    .read = tmpfs_read,
    .write = tmpfs_write,
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
    if (IS_ERR(ASSERT(inode)))
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
    if (IS_ERR(ASSERT(root))) {
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
    slab_init(&tmpfs_inode_slab, "tmpfs_inode", sizeof(struct tmpfs_inode));
    slab_init(&tmpfs_dentry_slab, "tmpfs_dentry", sizeof(struct tmpfs_dentry));

    static struct file_system fs = {
        .name = "tmpfs",
        .mount = tmpfs_mount,
        .create_inode = tmpfs_create_inode,
    };
    ASSERT_OK(file_system_register(&fs));
}
