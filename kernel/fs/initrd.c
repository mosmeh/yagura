#include "fs.h"
#include <common/extra.h>
#include <kernel/api/fcntl.h>
#include <kernel/boot_defs.h>
#include <kernel/fs/path.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <string.h>

struct cpio_odc_header {
    char c_magic[6];
    char c_dev[6];
    char c_ino[6];
    char c_mode[6];
    char c_uid[6];
    char c_gid[6];
    char c_nlink[6];
    char c_rdev[6];
    char c_mtime[11];
    char c_namesize[6];
    char c_filesize[11];
} __attribute__((packed));

static size_t parse_octal(const char* s, size_t len) {
    size_t res = 0;
    for (size_t i = 0; i < len; ++i) {
        res += s[i] - '0';
        if (i < len - 1)
            res *= 8;
    }
    return res;
}

#define PARSE(field) parse_octal(field, sizeof(field))

void initrd_populate_root_fs(uintptr_t phys_addr, size_t size) {
    uintptr_t map_start = round_down(phys_addr, PAGE_SIZE);
    size_t map_size = phys_addr + size - map_start;
    void* map =
        vm_phys_map(map_start, map_size, VM_READ | VM_WRITE | VM_SHARED);
    ASSERT_OK(map);

    struct path* root = vfs_get_root();
    ASSERT_OK(root);

    uintptr_t cursor = (uintptr_t)map + phys_addr - map_start;
    for (;;) {
        const struct cpio_odc_header* header =
            (const struct cpio_odc_header*)cursor;
        ASSERT(!strncmp(header->c_magic, "070707", 6));

        size_t name_size = PARSE(header->c_namesize);
        const char* filename =
            (const char*)(cursor + sizeof(struct cpio_odc_header));
        if (!strncmp(filename, "TRAILER!!!", name_size))
            break;

        size_t mode = PARSE(header->c_mode);
        size_t file_size = PARSE(header->c_filesize);

        if (S_ISDIR(mode)) {
            struct inode* inode = vfs_create_at(root, filename, mode);
            ASSERT_OK(inode);
            inode_unref(inode);
        } else {
            file_description* desc =
                vfs_open_at(root, filename, O_CREAT | O_EXCL | O_WRONLY, mode);
            ASSERT_OK(desc);

            desc->inode->rdev = PARSE(header->c_rdev);

            const unsigned char* file_content =
                (const unsigned char*)(cursor + sizeof(struct cpio_odc_header) +
                                       name_size);
            for (size_t count = 0; count < file_size;) {
                ssize_t nwritten = file_description_write(
                    desc, file_content + count, file_size - count);
                ASSERT_OK(nwritten);
                count += nwritten;
            }

            ASSERT_OK(file_description_close(desc));
        }

        cursor += sizeof(struct cpio_odc_header) + name_size + file_size;
    }

    path_destroy_recursive(root);
    kfree(map);
}
