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
    ASSERT(!inode->next);

    struct filemap* filemap = ASSERT(filemap_create(inode));
    if (IS_ERR(filemap))
        return PTR_ERR(filemap);
    inode->filemap = filemap;

    inode->mount = mount;

    SCOPED_LOCK(mount, mount);

    inode->flags |= INODE_READY;
    for (struct inode* it = mount->inodes; it; it = it->next)
        ASSERT(it->ino != inode->ino);
    inode->next = mount->inodes;
    mount->inodes = inode_ref(inode);

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
    struct inode* inode = mount->inodes;
    for (; inode; inode = inode->next) {
        if (inode->ino == ino)
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
    for (struct inode* inode = mount->inodes; inode; inode = inode->next) {
        if (!(inode->flags & INODE_DIRTY))
            continue;
        int rc = inode_sync(inode, 0, UINT64_MAX);
        if (IS_ERR(rc))
            return rc;
    }
    return 0;
}
