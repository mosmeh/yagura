#pragma once

#include <kernel/resource.h>

struct buf {
    struct inode* inode;
    struct page* page;
    size_t offset;
    size_t size;
    void* data;
};

// Reads the buffer for the given block index.
struct buf* buf_read(struct inode*, size_t block, size_t size);

// Releases the buffer, marking it dirty so it will be written back.
void buf_commit(struct buf*);

// Releases the buffer without marking it dirty.
void buf_discard(struct buf*);

DEFINE_FREE(buf, struct buf*, buf_discard)
