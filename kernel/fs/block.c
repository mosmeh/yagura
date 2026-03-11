#include "block.h"
#include "private.h"
#include <common/integer.h>
#include <common/string.h>
#include <kernel/device/device.h>
#include <kernel/memory/phys.h>

static struct slab block_slab;

void block_init(void) {
    SLAB_INIT_FOR_TYPE(&block_slab, "block", struct block);
}

int bcache_init(struct bcache* bc, struct block_dev* dev, uint8_t block_bits) {
    if (block_bits < SECTOR_SHIFT || PAGE_SHIFT < block_bits)
        return -EINVAL;
    *bc = (struct bcache){
        .dev = block_dev_ref(dev),
        .block_bits = block_bits,
    };
    return 0;
}

static struct filemap* bcache_filemap(struct bcache* bc) {
    return bc->dev->vfs_inode.filemap;
}

struct block* bcache_get(struct bcache* bc, uint64_t index, unsigned flags) {
    if ((flags & VM_WRITE) && !bc->dev->bops->write)
        return ERR_PTR(-EPERM);

    struct page* page FREE(page) = NULL;
    {
        size_t page_index = index << (bc->block_bits - PAGE_SHIFT);
        struct filemap* filemap = bcache_filemap(bc);
        SCOPED_LOCK(inode, filemap->inode);
        page = ASSERT(filemap_ensure_page(filemap, page_index));
    }
    if (IS_ERR(page))
        return ERR_CAST(page);

    struct block* block = ASSERT(slab_alloc(&block_slab));
    if (IS_ERR(block))
        return block;
    size_t offset = (index << bc->block_bits) % PAGE_SIZE;
    unsigned char* mapped_page = kmap_page(page, flags);
    *block = (struct block){
        .cache = bc,
        .page = TAKE_PTR(page),
        .offset = offset,
        .data = mapped_page + offset,
    };
    return block;
}

int bcache_sync(struct bcache* bc, size_t start, size_t end) {
    struct filemap* filemap = bcache_filemap(bc);
    uint8_t shift = bc->block_bits - PAGE_SHIFT;
    SCOPED_LOCK(inode, filemap->inode);
    return filemap_sync(filemap, start << shift, end << shift);
}

ssize_t bcache_read(struct bcache* bc, void* buffer, size_t count,
                    uint64_t offset) {
    if (count == 0)
        return 0;
    if (offset + count < offset)
        return -EOVERFLOW;

    struct block_dev* dev = bc->dev;
    SCOPED_LOCK(block_dev, bc->dev);

    size_t dev_size = dev->num_blocks << dev->block_bits;
    if (offset >= dev_size)
        return 0;
    count = MIN(count, dev_size - offset);

    struct filemap* filemap = bcache_filemap(bc);
    size_t nread = 0;
    unsigned char* dest = buffer;
    while (nread < count) {
        size_t page_index = offset >> PAGE_SHIFT;
        size_t page_offset = offset % PAGE_SIZE;
        struct page* page FREE(page) =
            ASSERT(filemap_ensure_page(filemap, page_index));
        if (IS_ERR(page))
            return PTR_ERR(page);

        size_t to_read = MIN(count - nread, PAGE_SIZE - page_offset);
        page_copy_to_buffer(page, dest, page_offset, to_read);

        dest += to_read;
        nread += to_read;
        offset += to_read;
    }
    return nread;
}

ssize_t bcache_write(struct bcache* bc, const void* buffer, size_t count,
                     uint64_t offset) {
    if (count == 0)
        return 0;
    if (offset + count < offset)
        return -EOVERFLOW;

    struct block_dev* dev = bc->dev;
    if (!dev->bops->write)
        return -EINVAL;
    SCOPED_LOCK(block_dev, dev);

    size_t dev_size = dev->num_blocks << dev->block_bits;
    if (offset >= dev_size)
        return -ENOSPC;
    count = MIN(count, dev_size - offset);

    struct filemap* filemap = bcache_filemap(bc);
    size_t nwritten = 0;
    const unsigned char* src = buffer;
    while (nwritten < count) {
        size_t page_index = offset >> PAGE_SHIFT;
        size_t page_offset = offset % PAGE_SIZE;
        struct page* page FREE(page) =
            ASSERT(filemap_ensure_page(filemap, page_index));
        if (IS_ERR(page))
            return PTR_ERR(page);

        size_t to_write = MIN(count - nwritten, PAGE_SIZE - page_offset);
        page_copy_from_buffer(page, src, page_offset, to_write);

        page->flags |= PAGE_DIRTY;
        dev->vfs_inode.flags |= INODE_DIRTY;

        src += to_write;
        nwritten += to_write;
        offset += to_write;
    }
    return nwritten;
}

void block_commit(struct block* block) {
    block->page->flags |= PAGE_DIRTY;
    block->cache->dev->vfs_inode.flags |= INODE_DIRTY;
    block_discard(block);
}

void block_discard(struct block* block) {
    if (!block)
        return;
    void* mapped_page = (unsigned char*)block->data - block->offset;
    kunmap(mapped_page);
    slab_free(&block_slab, block);
}
