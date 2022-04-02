#include "fs.h"
#include <common/initrd.h>
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/err.h>
#include <kernel/api/stat.h>
#include <kernel/kmalloc.h>
#include <kernel/panic.h>

typedef struct initrd_file {
    struct file base_file;
    ino_t ino;
} initrd_file;

static uintptr_t initrd_addr;
static const initrd_header* header;
static const initrd_file_header* file_headers;
static initrd_file* file_nodes;

static ssize_t initrd_read(file_description* desc, void* buffer, size_t count) {
    initrd_file* ifile = (initrd_file*)desc->file;
    const initrd_file_header* header = file_headers + ifile->ino;
    if ((size_t)desc->offset >= header->length)
        return 0;
    if (desc->offset + count >= header->length)
        count = header->length - desc->offset;

    memcpy(buffer,
           (void*)(uintptr_t)(initrd_addr + header->offset + desc->offset),
           count);
    desc->offset += count;

    return count;
}

static struct file* initrd_lookup(struct file* file, const char* name) {
    (void)file;
    for (size_t i = 0; i < header->num_files; ++i)
        if (!strcmp(name, file_nodes[i].base_file.name))
            return (struct file*)(file_nodes + i);
    return ERR_PTR(-ENOENT);
}

static long initrd_readdir(file_description* desc, void* dirp,
                           unsigned int count) {
    uintptr_t buf = (uintptr_t)dirp;
    long nread = 0;

    while (count > 0 && (size_t)desc->offset < header->num_files) {
        struct file* file = (struct file*)(file_nodes + desc->offset);
        size_t name_len = strlen(file->name);
        size_t size = offsetof(dirent, name) + name_len + 1;
        if (count < size)
            break;

        dirent* dent = (dirent*)buf;
        dent->type = mode_to_dirent_type(file->mode);
        dent->record_len = size;
        strcpy(dent->name, file->name);
        dent->name[name_len] = '\0';

        ++desc->offset;
        nread += size;
        buf += size;
        count -= size;
    }

    if (nread == 0)
        return -EINVAL;
    return nread;
}

void initrd_init(uintptr_t addr) {
    initrd_addr = addr;
    header = (const initrd_header*)addr;
    file_headers = (const initrd_file_header*)(addr + sizeof(initrd_header));

    file_nodes = kmalloc(header->num_files * sizeof(initrd_file));
    ASSERT(file_nodes);
    for (size_t i = 0; i < header->num_files; ++i) {
        initrd_file* ifile = file_nodes + i;
        ifile->ino = i;

        struct file* file = (struct file*)ifile;
        memset(file, 0, sizeof(struct file));
        file->name = kstrndup(file_headers[i].name, 128);
        ASSERT(file->name);
        file->mode = S_IFREG;
        file->read = initrd_read;
    }
}

struct file* initrd_create_root(void) {
    initrd_file* root = kmalloc(sizeof(initrd_file));
    if (!root)
        return ERR_PTR(-ENOMEM);

    memset(root, 0, sizeof(initrd_file));

    struct file* file = (struct file*)root;
    file->name = kstrdup("initrd");
    if (!file->name)
        return ERR_PTR(-ENOMEM);

    file->mode = S_IFDIR;
    file->lookup = initrd_lookup;
    file->readdir = initrd_readdir;

    return file;
}
