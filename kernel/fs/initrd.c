#include <common/integer.h>
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/file.h>
#include <kernel/fs/fs.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

#define CPIO_ALIGNMENT 4
#define CPIO_FOOTER_MAGIC "TRAILER!!!"

struct cpio_header {
    char c_magic[6];
    char c_ino[8];
    char c_mode[8];
    char c_uid[8];
    char c_gid[8];
    char c_nlink[8];
    char c_mtime[8];
    char c_filesize[8];
    char c_devmajor[8];
    char c_devminor[8];
    char c_rdevmajor[8];
    char c_rdevminor[8];
    char c_namesize[8];
    char c_check[8];
};

static size_t parse_hex(const char* s, size_t len) {
    size_t n = 0;
    for (size_t i = 0; i < len; ++i) {
        char c = s[i];
        n <<= 4;
        if ('0' <= c && c <= '9')
            n += c - '0';
        else if ('a' <= c && c <= 'f')
            n += c - 'a' + 10;
        else if ('A' <= c && c <= 'F')
            n += c - 'A' + 10;
        else
            break;
    }
    return n;
}

#define PARSE_FIELD(field) parse_hex(field, sizeof(field))

void initrd_populate_root_fs(phys_addr_t phys_addr, size_t size) {
    kprint("initrd: populating root file system\n");

    void* initrd FREE(phys) = phys_map(phys_addr, size, VM_READ);
    ASSERT_PTR(initrd);

    const unsigned char* cursor = initrd;
    const unsigned char* end = cursor + size;
    while (cursor < end) {
        const struct cpio_header* header = (const void*)cursor;
        if (strncmp(header->c_magic, "070701", sizeof(header->c_magic)) != 0) {
            kprint("initrd: invalid cpio magic\n");
            return;
        }

        size_t name_size = PARSE_FIELD(header->c_namesize);
        const char* filename =
            (const char*)(cursor + sizeof(struct cpio_header));
        if (filename[name_size - 1] != '\0') {
            kprint("initrd: filename not null-terminated\n");
            return;
        }
        if (!strncmp(filename, CPIO_FOOTER_MAGIC, sizeof(CPIO_FOOTER_MAGIC)))
            return;

        mode_t mode = PARSE_FIELD(header->c_mode);
        dev_t rdev = makedev(PARSE_FIELD(header->c_rdevmajor),
                             PARSE_FIELD(header->c_rdevminor));
        size_t file_size = PARSE_FIELD(header->c_filesize);

        const unsigned char* content = (const void*)ROUND_UP(
            (uintptr_t)(filename + name_size), CPIO_ALIGNMENT);
        cursor = (const void*)ROUND_UP((uintptr_t)(content + file_size),
                                       CPIO_ALIGNMENT);

        if (!S_ISREG(mode) && !S_ISLNK(mode)) {
            struct inode* inode FREE(inode) = vfs_create(filename, mode);
            if (IS_OK(ASSERT(inode)))
                inode->rdev = rdev;
            continue;
        }

        struct file* file FREE(file) =
            vfs_open(filename, O_CREAT | O_WRONLY, mode);
        if (IS_ERR(ASSERT(file)))
            continue;

        file->inode->rdev = rdev;

        if (file_size == 0)
            continue;

        ASSERT_OK(file_truncate(file, file_size));

        struct vm_obj* obj FREE(vm_obj) = file_mmap(file);
        ASSERT_PTR(obj);

        unsigned char* dest = vm_obj_map(obj, 0, DIV_CEIL(file_size, PAGE_SIZE),
                                         VM_WRITE | VM_SHARED);
        ASSERT_PTR(dest);
        memcpy(dest, content, file_size);
        vm_obj_unmap(dest);
    }

    kprint("initrd: premature end of archive\n");
}
