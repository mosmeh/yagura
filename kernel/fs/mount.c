#include "private.h"
#include <kernel/fs/inode.h>
#include <kernel/fs/vfs.h>

int mount_commit_inode(struct mount* mount, struct inode* inode) {
    ASSERT(!(inode->flags & INODE_READY));
    ASSERT_PTR(inode->iops);
    ASSERT_PTR(inode->fops);
    ASSERT(inode->ino > 0);
    ASSERT(inode->mode & S_IFMT);
    ASSERT(refcount_get(&inode->vm_obj.refcount) > 0);

    struct filemap* filemap = ASSERT(filemap_create(inode));
    if (IS_ERR(filemap))
        return PTR_ERR(filemap);
    inode->filemap = filemap;

    inode->mount = mount;

    SCOPED_LOCK(mount, mount);

    inode->flags |= INODE_READY;

    struct tree_node** new_node = &mount->inodes.root;
    struct tree_node* parent = NULL;
    while (*new_node) {
        parent = *new_node;
        struct inode* n = CONTAINER_OF(parent, struct inode, tree_node);
        if (inode->ino < n->ino)
            new_node = &parent->left;
        else if (inode->ino > n->ino)
            new_node = &parent->right;
        else
            PANIC("Duplicate ino");
    }
    *new_node = &inode->tree_node;
    inode_ref(inode);
    tree_insert(&mount->inodes, parent, &inode->tree_node);

    return 0;
}

struct inode* mount_create_inode(struct mount* mount, mode_t mode) {
    ASSERT(mode & S_IFMT);

    if (!mount->fs->create_inode)
        return ERR_PTR(-EROFS);

    struct inode* inode FREE(inode) =
        ASSERT(mount->fs->create_inode(mount, mode));
    if (IS_ERR(inode))
        return inode;

    int rc = mount_commit_inode(mount, inode);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    return TAKE_PTR(inode);
}

struct inode* mount_lookup_inode(struct mount* mount, ino_t ino) {
    ASSERT(ino > 0);
    SCOPED_LOCK(mount, mount);
    struct tree_node* node = mount->inodes.root;
    while (node) {
        struct inode* inode = CONTAINER_OF(node, struct inode, tree_node);
        if (ino < inode->ino)
            node = node->left;
        else if (ino > inode->ino)
            node = node->right;
        else
            return inode_ref(inode);
    }
    return NULL;
}

void mount_set_root(struct mount* mount, struct inode* inode) {
    ASSERT(inode->flags & INODE_READY);
    ASSERT(refcount_get(&inode->vm_obj.refcount) > 0);

    SCOPED_LOCK(mount, mount);
    ASSERT(!mount->root);
    mount->root = inode_ref(inode);
}

int mount_sync(struct mount* mount) {
    SCOPED_LOCK(mount, mount);
    for (struct tree_node* node = tree_first(&mount->inodes); node;
         node = tree_next(node)) {
        struct inode* inode = CONTAINER_OF(node, struct inode, tree_node);
        if (!(inode->flags & INODE_DIRTY))
            continue;
        int rc = inode_sync(inode, 0, UINT64_MAX);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}
