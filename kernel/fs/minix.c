#include <common/string.h>
#include <kernel/device/device.h>
#include <kernel/fs/buf.h>
#include <kernel/fs/fs.h>
#include <kernel/fs/path.h>
#include <kernel/kmsg.h>

#define BLOCK_SIZE 1024
#define MINIX_ROOT_INO 1
#define MINIX1_SUPER_MAGIC 0x137f  // original minix fs
#define MINIX1_SUPER_MAGIC2 0x138f // minix fs, 30 char names
#define MINIX2_SUPER_MAGIC 0x2468  // minix V2 fs
#define MINIX2_SUPER_MAGIC2 0x2478 // minix V2 fs, 30 char names

struct minix1_inode {
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size;
    uint32_t i_time;
    uint8_t i_gid;
    uint8_t i_nlinks;
    uint16_t i_zone[9];
};

struct minix2_inode {
    uint16_t i_mode;
    uint16_t i_nlinks;
    uint16_t i_uid;
    uint16_t i_gid;
    uint32_t i_size;
    uint32_t i_atime;
    uint32_t i_mtime;
    uint32_t i_ctime;
    uint32_t i_zone[10];
};

struct minix_superblock {
    uint16_t s_ninodes;
    uint16_t s_nzones;
    uint16_t s_imap_blocks;
    uint16_t s_zmap_blocks;
    uint16_t s_firstdatazone;
    uint16_t s_log_zone_size;
    uint32_t s_max_size;
    uint16_t s_magic;
    uint16_t s_state;
    uint32_t s_zones;
};

struct minix_dir_entry {
    uint16_t inode;
    char name[];
};

struct minix_mount {
    struct mount vfs_mount;
    struct block_dev* block_dev;

    size_t max_ninodes;
    size_t first_data_block;

    size_t name_len;
    size_t dir_entry_size;

    size_t imap_nblocks;
    unsigned char* imap;

    size_t zmap_nblocks;
    unsigned char* zmap;
};

struct minix_inode {
    struct inode vfs_inode;
};

static struct slab inode_slab;

static void minix_destroy(struct inode* vfs_inode) {
    struct minix_inode* inode =
        CONTAINER_OF(vfs_inode, struct minix_inode, vfs_inode);
    slab_free(&inode_slab, inode);
}

static struct inode* minix_lookup(struct inode* parent, const char* name) {
    UNIMPLEMENTED();
}

static int minix_link(struct inode* parent, const char* name,
                      struct inode* child) {

    UNIMPLEMENTED();
}

static int minix_unlink(struct inode* parent, const char* name) {
    UNIMPLEMENTED();
}

static int minix_read(struct inode* inode, struct page* page,
                      size_t page_index) {
    UNIMPLEMENTED();
}

static int minix_write(struct inode* inode, struct page* page,
                       size_t page_index) {
    UNIMPLEMENTED();
}

static const struct inode_ops minix_file_iops = {
    .destroy = minix_destroy,
    .read = minix_read,
    .write = minix_write,
};
static const struct inode_ops minix_dir_iops = {
    .destroy = minix_destroy,
    .lookup = minix_lookup,
    .link = minix_link,
    .unlink = minix_unlink,
};

static struct inode* get_inode(struct minix_mount* mount, ino_t ino) {
    if (ino == 0 || ino > mount->max_ninodes)
        return ERR_PTR(-ENOENT);

    SCOPED_LOCK(mount, &mount->vfs_mount);

    struct inode* vfs_inode = mount_lookup_inode(&mount->vfs_mount, ino);
    if (vfs_inode)
        return vfs_inode;

    struct minix_inode* inode = slab_alloc(&inode_slab);
    if (IS_ERR(ASSERT(inode)))
        return ERR_CAST(inode);
    *inode = (struct minix_inode){
        .vfs_inode = INODE_INIT,
    };

    vfs_inode = &inode->vfs_inode;
    vfs_inode->ino = ino;
    vfs_inode->iops = &minix_file_iops; // TODO: set dir iops if directory

    int rc = mount_commit_inode(&mount->vfs_mount, vfs_inode);
    if (IS_ERR(rc)) {
        slab_free(&inode_slab, inode);
        return ERR_PTR(rc);
    }
    return vfs_inode;
}

static struct buf* bread(struct minix_mount* mount, size_t block) {
    struct inode* inode = &mount->block_dev->vfs_inode;
    return buf_read(inode, block, BLOCK_SIZE);
}

static struct mount* minix_mount(const char* source) {
    struct path* path FREE(path) = vfs_resolve_path(source, 0);
    if (IS_ERR(ASSERT(path)))
        return ERR_CAST(path);

    struct block_dev* block_dev FREE(block_dev) =
        block_dev_get(path->inode->rdev);
    if (!block_dev)
        return ERR_PTR(-ENOENT);

    struct minix_mount* mount FREE(kfree) = kmalloc(sizeof(struct minix_mount));
    if (!mount)
        return ERR_PTR(-ENOMEM);
    *mount = (struct minix_mount){
        .block_dev = block_dev,
    };
    struct mount* vfs_mount = &mount->vfs_mount;

    size_t superblock_block = 1;
    {
        struct buf* buf FREE(buf) = bread(mount, superblock_block);
        if (IS_ERR(ASSERT(buf)))
            return ERR_CAST(buf);

        struct minix_superblock* sb = buf->data;
        switch (sb->s_magic) {
        case MINIX1_SUPER_MAGIC:
        case MINIX2_SUPER_MAGIC:
            mount->dir_entry_size = 16;
            mount->name_len = 14;
            break;
        case MINIX1_SUPER_MAGIC2:
        case MINIX2_SUPER_MAGIC2:
            mount->dir_entry_size = 32;
            mount->name_len = 30;
            break;
        default:
            kprintf("minix: unsupported superblock magic: %#04x\n",
                    sb->s_magic);
            return ERR_PTR(-EINVAL);
        }
        if (!sb->s_imap_blocks || !sb->s_zmap_blocks) {
            kprintf("minix: s_imap_blocks or s_zmap_blocks is zero\n");
            return ERR_PTR(-EINVAL);
        }
        mount->max_ninodes = sb->s_ninodes;
        mount->imap_nblocks = sb->s_imap_blocks;
        mount->zmap_nblocks = sb->s_zmap_blocks;
    }

    size_t imap_block = superblock_block + 1;
    size_t imap_size = mount->imap_nblocks * BLOCK_SIZE;
    unsigned char* imap FREE(kfree) = kmalloc(imap_size);
    if (!imap)
        return ERR_PTR(-ENOMEM);
    for (size_t i = 0; i < mount->imap_nblocks; ++i) {
        struct buf* buf FREE(buf) = bread(mount, imap_block + i);
        if (IS_ERR(ASSERT(buf)))
            return ERR_CAST(buf);
        memcpy(imap + (i * BLOCK_SIZE), buf->data, BLOCK_SIZE);
    }

    size_t zmap_block = imap_block + mount->imap_nblocks;
    size_t zmap_size = mount->zmap_nblocks * BLOCK_SIZE;
    unsigned char* zmap FREE(kfree) = kmalloc(zmap_size);
    if (!zmap)
        return ERR_PTR(-ENOMEM);
    for (size_t i = 0; i < mount->zmap_nblocks; ++i) {
        struct buf* buf FREE(buf) = bread(mount, zmap_block + i);
        if (IS_ERR(ASSERT(buf)))
            return ERR_CAST(buf);
        memcpy(zmap + (i * BLOCK_SIZE), buf->data, BLOCK_SIZE);
    }

    struct inode* root FREE(inode) = get_inode(mount, MINIX_ROOT_INO);
    if (IS_ERR(ASSERT(root)))
        return ERR_CAST(root);
    mount_set_root(vfs_mount, root);

    mount->imap = TAKE_PTR(imap);
    mount->zmap = TAKE_PTR(zmap);
    TAKE_PTR(mount);
    TAKE_PTR(block_dev);
    return vfs_mount;
}

static struct inode* minix_create_inode(struct mount* vfs_mount, mode_t mode) {
    (void)mode;

    struct minix_mount* mount =
        CONTAINER_OF(vfs_mount, struct minix_mount, vfs_mount);

    // TODO: allocate ino
    return get_inode(mount, 0);
}

void minix_init(void) {
    slab_init(&inode_slab, "minix_inode", sizeof(struct minix_inode));

    static struct file_system fs = {
        .name = "minix",
        .mount = minix_mount,
        .create_inode = minix_create_inode,
    };
    ASSERT_OK(file_system_register(&fs));
}
