#include "block.h"
#include "private.h"
#include <common/integer.h>
#include <common/string.h>
#include <kernel/device/device.h>
#include <kernel/memory/phys.h>

static struct slab block_slab;

void block_init(void) { SLAB_INIT(&block_slab, "block", struct block); }

static struct block* create(struct block_dev* dev, uint64_t index,
                            size_t size) {
    uint64_t offset = index * size;
    size_t page_index = offset >> PAGE_SHIFT;
    struct page* page FREE(page) =
        ASSERT(filemap_ensure_page(dev->vfs_inode.filemap, page_index));
    if (IS_ERR(page))
        return ERR_CAST(page);

    struct block* block = ASSERT(slab_alloc(&block_slab));
    if (IS_ERR(block))
        return block;
    *block = (struct block){
        .dev = block_dev_ref(dev),
        .page = TAKE_PTR(page),
        .offset = offset % PAGE_SIZE,
        .size = size,
    };
    return block;
}

struct block* block_load(struct block_dev* dev, uint64_t index, size_t size) {
    if (size < SECTOR_SIZE || PAGE_SIZE < size || (size % SECTOR_SIZE))
        return ERR_PTR(-EINVAL);

    block_dev_lock(dev);

    struct block* block = ASSERT(create(dev, index, size));
    if (IS_ERR(block)) {
        block_dev_unlock(dev);
        return block;
    }

    unsigned char* mapped_page = kmap_page(block->page, VM_READ | VM_WRITE);
    block->data = mapped_page + block->offset;
    return block;
}

void block_commit(struct block* block) {
    block->page->flags |= PAGE_DIRTY;
    block->dev->vfs_inode.flags |= INODE_DIRTY;
    block_discard(block);
}

void block_discard(struct block* block) {
    if (!block)
        return;

    void* mapped_page = (unsigned char*)block->data - block->offset;
    kunmap(mapped_page);

    struct block_dev* dev = block->dev;
    slab_free(&block_slab, block);
    block_dev_unlock(dev);
    block_dev_unref(dev);
}

ssize_t block_read(struct block_dev* dev, void* buffer, size_t count,
                   uint64_t offset) {
    if (count == 0)
        return 0;
    if (offset + count < offset)
        return -EOVERFLOW;

    SCOPED_LOCK(block_dev, dev);

    size_t dev_size = dev->num_blocks << dev->block_bits;
    if (offset >= dev_size)
        return 0;
    count = MIN(count, dev_size - offset);

    struct filemap* filemap = dev->vfs_inode.filemap;
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

ssize_t block_write(struct block_dev* dev, const void* buffer, size_t count,
                    uint64_t offset) {
    if (count == 0)
        return 0;
    if (offset + count < offset)
        return -EOVERFLOW;

    SCOPED_LOCK(block_dev, dev);

    if (!dev->bops->write)
        return -EINVAL;

    size_t dev_size = dev->num_blocks << dev->block_bits;
    if (offset >= dev_size)
        return -ENOSPC;
    count = MIN(count, dev_size - offset);

    struct filemap* filemap = dev->vfs_inode.filemap;
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
