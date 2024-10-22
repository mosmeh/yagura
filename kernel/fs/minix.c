#include "fs.h"
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stdio.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

#define BLOCK_SIZE 1024
#define MINIX1_SUPER_MAGIC 0x137f  // original minix fs
#define MINIX1_SUPER_MAGIC2 0x138f // minix fs, 30 char names
#define MINIX2_SUPER_MAGIC 0x2468  // minix V2 fs
#define MINIX2_SUPER_MAGIC2 0x2478 // minix V2 fs, 30 char names
#define MINIX_ROOT_INO 1

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

struct minix_root_node {
    struct inode inode;
    struct file* file;
    struct minix_superblock superblock;
    size_t dir_size;
    size_t name_len;
};

static struct inode* minix_mount(const char* source) {
    struct file* file = vfs_open(source, O_RDWR, 0);
    if (IS_ERR(file))
        return ERR_CAST(file);

    int ret = file_seek(file, BLOCK_SIZE, SEEK_SET);
    if (IS_ERR(ret))
        goto fail;

    struct minix_superblock superblock;
    ret = file_read_to_end(file, &superblock, sizeof(superblock));
    if (IS_ERR(ret))
        goto fail;

    size_t dir_size;
    size_t name_len;
    switch (superblock.s_magic) {
    case MINIX1_SUPER_MAGIC:
    case MINIX2_SUPER_MAGIC:
        dir_size = 16;
        name_len = 14;
        break;
    case MINIX1_SUPER_MAGIC2:
    case MINIX2_SUPER_MAGIC2:
        dir_size = 32;
        name_len = 30;
        break;
    default:
        ret = -EINVAL;
        goto fail;
    }

    if (superblock.s_imap_blocks == 0 || superblock.s_zmap_blocks == 0) {
        ret = -EINVAL;
        goto fail;
    }

    struct minix_root_node* root = kmalloc(sizeof(struct minix_root_node));
    if (!root) {
        ret = -ENOMEM;
        goto fail;
    }
    *root = (struct minix_root_node){
        .file = file,
        .superblock = superblock,
        .dir_size = dir_size,
        .name_len = name_len,
    };

    static const struct file_ops fops = {0};
    struct inode* inode = &root->inode;
    inode->vm_obj = INODE_VM_OBJ_INIT;
    inode->dev = vfs_generate_unnamed_block_device_number();
    inode->fops = &fops;
    inode->mode = S_IFDIR;

    return inode;

fail:
    file_unref(file);
    return ERR_PTR(ret);
}

void minix_init(void) {
    static struct file_system fs = {
        .name = "minix",
        .mount = minix_mount,
    };
    ASSERT_OK(vfs_register_file_system(&fs));
}
