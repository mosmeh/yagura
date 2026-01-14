#include <common/integer.h>
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/fs/file.h>
#include <kernel/fs/fs.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

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

#define PARSE_FIELD(field) parse_octal(field, sizeof(field))

void initrd_populate_root_fs(phys_addr_t phys_addr, size_t size) {
    kprint("initrd: populating root file system\n");

    void* initrd FREE(phys) = phys_map(phys_addr, size, VM_READ);
    ASSERT_PTR(initrd);

    unsigned char* cursor = initrd;
    for (;;) {
        const struct cpio_odc_header* header = (const void*)cursor;
        ASSERT(!strncmp(header->c_magic, "070707", 6));

        size_t name_size = PARSE_FIELD(header->c_namesize);
        char* filename = (char*)(cursor + sizeof(struct cpio_odc_header));
        if (!strncmp(filename, "TRAILER!!!", name_size))
            break;

        size_t mode = PARSE_FIELD(header->c_mode);
        mode_t rdev = PARSE_FIELD(header->c_rdev);
        size_t file_size = PARSE_FIELD(header->c_filesize);
        unsigned char* content = (void*)(filename + name_size);

        if (S_ISREG(mode) || S_ISLNK(mode)) {
            struct file* file FREE(file) =
                vfs_open(filename, O_CREAT | O_EXCL | O_WRONLY, mode);
            ASSERT_PTR(file);

            file->inode->rdev = rdev;

            if (file_size > 0) {
                ASSERT_OK(file_truncate(file, file_size));

                struct vm_obj* obj FREE(vm_obj) = file_mmap(file);
                ASSERT_PTR(obj);

                unsigned char* dest =
                    vm_obj_map(obj, 0, DIV_CEIL(file_size, PAGE_SIZE),
                               VM_WRITE | VM_SHARED);
                ASSERT_PTR(dest);
                memcpy(dest, content, file_size);
                vm_obj_unmap(dest);
            }
        } else {
            struct inode* inode FREE(inode) = vfs_create(filename, mode);
            ASSERT_PTR(inode);
            inode->rdev = rdev;
        }

        cursor = content + file_size;
    }
}
