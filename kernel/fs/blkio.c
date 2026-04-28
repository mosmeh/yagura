#include "private.h"
#include <common/integer.h>
#include <kernel/device/block.h>
#include <kernel/fs/blkio.h>
#include <kernel/fs/inode.h>

void __blkio_init(struct blkio* io, struct block_dev* dev, uint8_t block_bits) {
    *io = (struct blkio){
        .dev = block_dev_ref(dev),
        .block_bits = block_bits,
    };
    block_dev_lock(io->dev);
}

void __blkio_deinit(struct blkio* io) {
    blkio_unmap(io);
    block_dev_unlock(io->dev);
    block_dev_unref(io->dev);
}

static uint64_t dev_size(struct blkio* io) {
    return io->dev->num_blocks << io->dev->block_bits;
}

static struct filemap* blkio_filemap(struct blkio* io) {
    return io->dev->vfs_inode.filemap;
}

void* blkio_map(struct blkio* io, uint64_t block_index, unsigned flags) {
    ASSERT(!io->page);

    if (io->block_bits < SECTOR_SHIFT || PAGE_SHIFT < io->block_bits)
        return ERR_PTR(-EINVAL);

    if (block_index >= (UINT64_MAX >> io->block_bits))
        return ERR_PTR(-EOVERFLOW);

    uint64_t offset = block_index << io->block_bits;
    if (offset >= dev_size(io))
        return ERR_PTR(-EINVAL);

    uint64_t end = (block_index + 1) << io->block_bits;
    if (end > dev_size(io))
        return ERR_PTR(-EINVAL);

    uint64_t page_index = block_index >> (PAGE_SHIFT - io->block_bits);
    if (page_index > SIZE_MAX)
        return ERR_PTR(-EOVERFLOW);

    if ((flags & VM_WRITE) && !io->dev->bops->write)
        return ERR_PTR(-EPERM);

    struct filemap* filemap = ASSERT_PTR(blkio_filemap(io));
    struct page* page FREE(page) =
        ASSERT(filemap_ensure_page(filemap, page_index));
    if (IS_ERR(page))
        return ERR_CAST(page);

    unsigned char* mapped_page = kmap_page(page, flags);
    io->page = TAKE_PTR(page);
    io->addr = mapped_page + (offset % PAGE_SIZE);
    io->flags = flags;

    return io->addr;
}

static void mark_dirty(struct blkio* io, struct page* page) {
    page->flags |= PAGE_DIRTY;
    io->dev->vfs_inode.flags |= INODE_DIRTY;
}

void blkio_mark_dirty(struct blkio* io) {
    ASSERT(io->page);
    ASSERT(io->flags & VM_WRITE);
    mark_dirty(io, io->page);
}

void blkio_unmap(struct blkio* io) {
    if (!io->page)
        return;
    kunmap((void*)ROUND_DOWN((uintptr_t)io->addr, PAGE_SIZE));
    io->page = NULL;
    io->flags = 0;
}

ssize_t blkio_read(struct blkio* io, void* buffer, size_t count,
                   uint64_t offset) {
    if (count == 0)
        return 0;
    if (offset + count < offset)
        return -EOVERFLOW;

    struct block_dev* dev = io->dev;
    ASSERT_PTR(dev->bops->read);

    uint64_t size = dev_size(io);
    if (offset >= size)
        return 0;
    count = MIN(count, size - offset);

    struct filemap* filemap = ASSERT_PTR(blkio_filemap(io));
    size_t nread = 0;
    unsigned char* dest = buffer;
    size_t page_offset = offset % PAGE_SIZE;
    while (nread < count) {
        size_t page_index = offset >> PAGE_SHIFT;
        struct page* page FREE(page) =
            ASSERT(filemap_ensure_page(filemap, page_index));
        if (IS_ERR(page))
            return PTR_ERR(page);

        size_t to_read = MIN(count - nread, PAGE_SIZE - page_offset);
        copy_from_page(dest, page, page_offset, to_read);

        dest += to_read;
        nread += to_read;
        offset += to_read;
        page_offset = 0;
    }

    return nread;
}

ssize_t blkio_write(struct blkio* io, const void* buffer, size_t count,
                    uint64_t offset) {
    if (count == 0)
        return 0;
    if (offset + count < offset)
        return -EOVERFLOW;

    struct block_dev* dev = io->dev;
    if (!dev->bops->write)
        return -EPERM;

    uint64_t size = dev_size(io);
    if (offset >= size)
        return -ENOSPC;
    count = MIN(count, size - offset);

    struct filemap* filemap = ASSERT_PTR(blkio_filemap(io));
    size_t nwritten = 0;
    const unsigned char* src = buffer;
    size_t page_offset = offset % PAGE_SIZE;
    while (nwritten < count) {
        size_t page_index = offset >> PAGE_SHIFT;
        struct page* page FREE(page) =
            ASSERT(filemap_ensure_page(filemap, page_index));
        if (IS_ERR(page))
            return PTR_ERR(page);

        size_t to_write = MIN(count - nwritten, PAGE_SIZE - page_offset);
        copy_to_page(page, src, page_offset, to_write);
        mark_dirty(io, page);

        src += to_write;
        nwritten += to_write;
        offset += to_write;
        page_offset = 0;
    }

    return nwritten;
}
