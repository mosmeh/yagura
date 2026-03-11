#pragma once

#include <common/macros.h>
#include <common/tree.h>
#include <kernel/memory/phys.h>

struct inode;

void file_init(void);
void path_init(void);
void filemap_init(void);
void block_init(void);
void vfs_init(void);
void pipe_init(void);
void ramfs_init(void);
void ext2_init(void);
void minix_init(void);
void proc_init(void);

struct file* file_create(struct inode*, int flags);

extern const struct file_ops pipe_fops;

struct filemap* filemap_create(struct inode*);
void filemap_destroy(struct filemap*);

// Ensures that the page at the given index exists in the filemap.
struct page* filemap_ensure_page(struct filemap*, size_t index);

// Writes back all dirty pages in the given range of indices.
NODISCARD int filemap_sync(struct filemap*, size_t start, size_t end);

// Attempts to evict all pages in the given range of indices, writing back
// dirty pages as necessary.
// Returns the number of evicted pages.
NODISCARD ssize_t filemap_evict(struct filemap*, size_t start, size_t end);

// Truncates the filemap to the given length.
NODISCARD int filemap_truncate(struct filemap*, uint64_t length);

void initramfs_populate_root_fs(phys_addr_t phys_addr, size_t size);
