#pragma once

#include "fs.h"

struct vec;

void filemap_init(void);
void vfs_init(const multiboot_module_t* initrd_mod);
void pipe_init(void);

extern const struct file_ops pipe_fops;

struct filemap {
    struct inode* inode;
    struct page* pages;
};

struct filemap* filemap_create(struct inode*);
void filemap_destroy(struct filemap*);

// Ensures that the page at the given index exists in the filemap.
// If `write` is true, the page is created even if it's outside the current size
// of the file.
struct page* filemap_ensure_page(struct filemap*, size_t index, bool write);

// Writes back all dirty pages in the given range of indices.
NODISCARD int filemap_sync(struct filemap*, size_t start, size_t end);

// Truncates the filemap to the given length.
NODISCARD int filemap_truncate(struct filemap*, uint64_t length);

typedef int (*proc_print_fn)(struct file*, struct vec*);

int proc_print_mounts(struct file*, struct vec*);
