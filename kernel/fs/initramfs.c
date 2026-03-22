#include <common/integer.h>
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/file.h>
#include <kernel/fs/inode.h>
#include <kernel/fs/path.h>
#include <kernel/fs/vfs.h>
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

struct entry {
    ino_t ino;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    nlink_t nlink;
    size_t file_size;
    dev_t dev;
    dev_t rdev;
    const char* pathname;
    size_t pathname_size;
    const unsigned char* content;
    struct tree_node node;
};

static int entry_cmp(const struct entry* a, const struct entry* b) {
    if (a->ino < b->ino)
        return -1;
    if (a->ino > b->ino)
        return 1;
    if (a->dev < b->dev)
        return -1;
    if (a->dev > b->dev)
        return 1;
    return 0;
}

static void copy_owner(struct inode* inode, const struct entry* entry) {
    inode->uid = entry->uid;
    inode->gid = entry->gid;
}

static struct tree links = {0};

NODISCARD
static const char* find_or_add_link(const struct entry* new_entry) {
    struct tree_node** new_node = &links.root;
    struct tree_node* parent = NULL;
    while (*new_node) {
        parent = *new_node;
        struct entry* entry = CONTAINER_OF(parent, struct entry, node);
        int cmp = entry_cmp(new_entry, entry);
        if (cmp < 0)
            new_node = &parent->left;
        else if (cmp > 0)
            new_node = &parent->right;
        else
            return entry->pathname;
    }
    struct entry* dup_entry = ASSERT_PTR(kmalloc(sizeof(struct entry)));
    *dup_entry = *new_entry;
    *new_node = &dup_entry->node;
    tree_insert(&links, parent, *new_node);
    return NULL;
}

static void free_links(void) {
    for (;;) {
        struct tree_node* node = tree_first(&links);
        if (!node)
            break;
        struct entry* entry = CONTAINER_OF(node, struct entry, node);
        tree_remove(&links, &entry->node);
        kfree(entry);
    }
}

static void on_regular_file(const struct entry* entry) {
    if (entry->nlink > 1) {
        const char* link_target = find_or_add_link(entry);
        if (link_target) {
            struct path* old_path FREE(path) =
                ASSERT(vfs_resolve_path(BASE_CWD, link_target, O_NOFOLLOW));
            if (IS_ERR(old_path))
                return;

            struct path* new_path FREE(path) = ASSERT(vfs_resolve_path(
                BASE_CWD, entry->pathname, O_ALLOW_NOENT | O_NOFOLLOW));
            if (IS_ERR(new_path) || !new_path->parent || new_path->inode)
                return;

            int rc = inode_link(new_path->parent->inode, new_path->basename,
                                old_path->inode);
            (void)rc;
        }
    }

    struct file* file FREE(file) = ASSERT(
        vfs_open(BASE_CWD, entry->pathname, O_CREAT | O_WRONLY, entry->mode));
    if (IS_ERR(file))
        return;

    if (entry->file_size > 0) {
        ASSERT_OK(file_truncate(file, entry->file_size));

        struct vm_obj* obj FREE(vm_obj) = ASSERT_PTR(file_mmap(file));
        unsigned char* dest =
            ASSERT_PTR(vm_obj_map(obj, 0, DIV_CEIL(entry->file_size, PAGE_SIZE),
                                  VM_WRITE | VM_SHARED));
        memcpy(dest, entry->content, entry->file_size);
        vm_obj_unmap(dest);
    }

    copy_owner(file->inode, entry);
}

static void on_directory(const struct entry* entry) {
    struct inode* inode FREE(inode) =
        ASSERT(vfs_create(BASE_CWD, entry->pathname, entry->mode));
    if (IS_ERR(inode))
        return;
    copy_owner(inode, entry);
}

static void on_non_regular_file(const struct entry* entry) {
    struct inode* inode FREE(inode) =
        ASSERT(vfs_mknod(BASE_CWD, entry->pathname, entry->mode, entry->rdev));
    if (IS_ERR(inode))
        return;
    copy_owner(inode, entry);
}

static void on_symlink(const struct entry* entry) {
    struct file* file FREE(file) = ASSERT(
        vfs_open(BASE_CWD, entry->pathname, O_CREAT | O_WRONLY, entry->mode));
    if (IS_ERR(file))
        return;

    int rc = file_symlink(file, (const char*)entry->content, entry->file_size);
    (void)rc;

    copy_owner(file->inode, entry);
}

static void on_entry(const struct entry* entry) {
    switch (entry->mode & S_IFMT) {
    case S_IFREG:
        on_regular_file(entry);
        break;
    case S_IFDIR:
        on_directory(entry);
        break;
    case S_IFCHR:
    case S_IFBLK:
    case S_IFIFO:
    case S_IFSOCK:
        on_non_regular_file(entry);
        break;
    case S_IFLNK:
        on_symlink(entry);
        break;
    }
}

static void unpack_image(const unsigned char* start, const unsigned char* end) {
    const unsigned char* cursor = start;
    while (cursor + sizeof(struct cpio_header) <= end) {
        const struct cpio_header* header = (const void*)cursor;
        if (strncmp(header->c_magic, "070701", sizeof(header->c_magic)) != 0) {
            kprint("initramfs: invalid cpio magic\n");
            return;
        }

        size_t name_size = PARSE_FIELD(header->c_namesize);
        const char* name = (const char*)(cursor + sizeof(struct cpio_header));
        if (name[name_size - 1] != '\0') {
            kprint("initramfs: filename not null-terminated\n");
            return;
        }
        if (!strncmp(name, CPIO_FOOTER_MAGIC, sizeof(CPIO_FOOTER_MAGIC)))
            return;

        struct entry entry = {
            .ino = PARSE_FIELD(header->c_ino),
            .mode = PARSE_FIELD(header->c_mode),
            .uid = PARSE_FIELD(header->c_uid),
            .gid = PARSE_FIELD(header->c_gid),
            .nlink = PARSE_FIELD(header->c_nlink),
            .file_size = PARSE_FIELD(header->c_filesize),
            .dev = makedev(PARSE_FIELD(header->c_devmajor),
                           PARSE_FIELD(header->c_devminor)),
            .rdev = makedev(PARSE_FIELD(header->c_rdevmajor),
                            PARSE_FIELD(header->c_rdevminor)),
            .pathname = name,
            .pathname_size = name_size,
            .content = (const void*)ROUND_UP((uintptr_t)(name + name_size),
                                             CPIO_ALIGNMENT),
        };
        on_entry(&entry);

        cursor = (const void*)ROUND_UP(
            (uintptr_t)(entry.content + entry.file_size), CPIO_ALIGNMENT);
    }

    kprint("initramfs: premature end of archive\n");
}

void initramfs_populate_root_fs(phys_addr_t phys_addr, size_t size) {
    if (size < sizeof(struct cpio_header))
        return;

    kprint("initramfs: populating root file system\n");
    unsigned char* image FREE(phys) =
        ASSERT_PTR(phys_map(phys_addr, size, VM_READ));
    unpack_image(image, image + size);
    free_links();
}
