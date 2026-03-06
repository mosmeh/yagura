#pragma once

#include <kernel/api/sys/types.h>
#include <kernel/resource.h>

struct inode;

struct block {
    struct block_dev* dev;
    struct page* page;
    size_t offset;
    size_t size;
    void* data;
};

// Reads the block for the given block index.
struct block* block_load(struct block_dev*, size_t index, size_t size);

// Releases the block, marking it dirty so it will be written back.
void block_commit(struct block*);

// Releases the block without marking it dirty.
void block_discard(struct block*);

DEFINE_FREE(block, struct block*, block_discard)

NODISCARD ssize_t block_read(struct block_dev*, void* buffer, size_t count,
                             uint64_t offset);
NODISCARD ssize_t block_write(struct block_dev*, const void* buffer,
                              size_t count, uint64_t offset);
