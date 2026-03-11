#include "private.h"
#include <kernel/fs/vfs.h>

static struct mount* ext2_mount(const char* source) { UNIMPLEMENTED(); }

static struct inode* ext2_create_inode(struct mount* vfs_mount, mode_t mode) {
    UNIMPLEMENTED();
}

void ext2_init(void) {
    static struct file_system fs = {
        .name = "ext2",
        .mount = ext2_mount,
        .create_inode = ext2_create_inode,
    };
    ASSERT_OK(file_system_register(&fs));
}
