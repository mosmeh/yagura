#pragma once

#include <kernel/api/sys/types.h>
#include <kernel/resource.h>

struct inode;

struct bcache {
    struct block_dev* dev;
    uint8_t block_bits;
};

struct block {
    struct bcache* cache;
    struct page* page;
    size_t offset;
    void* data;
};

NODISCARD int bcache_init(struct bcache*, struct block_dev*,
                          uint8_t block_bits);

// Reads the block for the given block index.
struct block* bcache_get(struct bcache*, size_t index, unsigned flags);

NODISCARD ssize_t bcache_read(struct bcache*, void* buffer, size_t count,
                              uint64_t offset);
NODISCARD ssize_t bcache_write(struct bcache*, const void* buffer, size_t count,
                               uint64_t offset);

// Releases the block, marking it dirty so it will be written back.
void block_commit(struct block*);

// Releases the block without marking it dirty.
void block_discard(struct block*);

DEFINE_FREE(block, struct block, block_discard)
