#pragma once

#include <common/macros.h>
#include <kernel/api/sys/types.h>
#include <kernel/memory/vm.h>

// Example usage:
//
// int update_last_modified(struct block_dev* dev) {
//     SCOPED_BLKIO(io, dev, FS_BLOCK_SHIFT);
//     struct superblock* sb = blkio_map(&io, SB_INDEX, VM_WRITE);
//     if (IS_ERR(sb))
//         return PTR_ERR(sb);
//     sb->last_modified = now();
//     blkio_mark_dirty(&io);
//     // blkio_unmap(&io) is called automatically when io goes out of scope
//     return 0;
// }

#define SCOPED_BLKIO(name, dev, block_bits)                                    \
    struct blkio name CLEANUP(__blkio_deinit);                                 \
    __blkio_init(&(name), dev, block_bits);

struct blkio {
    struct block_dev* dev;
    struct page* page;
    void* addr;
    unsigned flags;
    uint8_t block_bits;
};

void __blkio_init(struct blkio*, struct block_dev*, uint8_t block_bits);
void __blkio_deinit(struct blkio*);

NODISCARD void* blkio_map(struct blkio*, uint64_t block_index, unsigned flags);
void blkio_mark_dirty(struct blkio*);
void blkio_unmap(struct blkio*);

NODISCARD ssize_t blkio_read(struct blkio*, void* buffer, size_t count,
                             uint64_t offset);
NODISCARD ssize_t blkio_write(struct blkio*, const void* buffer, size_t count,
                              uint64_t offset);
