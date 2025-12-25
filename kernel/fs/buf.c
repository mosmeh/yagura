#include "private.h"
#include <common/integer.h>
#include <kernel/device/device.h>
#include <kernel/fs/buf.h>
#include <kernel/memory/phys.h>

static struct slab buf_slab;

void buf_init(void) { slab_init(&buf_slab, "buf", sizeof(struct buf)); }

static struct buf* create_buf(struct inode* inode, size_t block, size_t size) {
    struct filemap* filemap = inode->filemap;

    size_t offset = block * size;
    size_t page_index = offset >> PAGE_SHIFT;
    struct page* page = filemap_ensure_page(filemap, page_index, false);
    if (IS_ERR(page))
        return ERR_CAST(page);
    if (!page) {
        // Out of bounds
        return ERR_PTR(-EINVAL);
    }

    struct buf* buf = slab_alloc(&buf_slab);
    if (IS_ERR(ASSERT(buf)))
        return buf;
    *buf = (struct buf){
        .inode = inode_ref(inode),
        .page = page,
        .offset = offset % PAGE_SIZE,
        .size = size,
    };
    return buf;
}

struct buf* buf_read(struct inode* inode, size_t block, size_t size) {
    if (size < SECTOR_SIZE || PAGE_SIZE < size || (size % SECTOR_SIZE))
        return ERR_PTR(-EINVAL);

    inode_lock(inode);

    struct buf* buf = create_buf(inode, block, size);
    if (IS_ERR(ASSERT(buf))) {
        inode_unlock(inode);
        return buf;
    }

    unsigned char* mapped_page = kmap_page(buf->page);
    buf->data = mapped_page + buf->offset;
    return buf;
}

void buf_commit(struct buf* buf) {
    size_t start = buf->offset >> SECTOR_SHIFT;
    size_t end = DIV_CEIL(buf->offset + buf->size, SECTOR_SIZE);
    for (size_t i = start; i < end; ++i)
        buf->page->dirty |= 1 << i;
    buf->inode->flags |= INODE_DIRTY;
    buf_discard(buf);
}

void buf_discard(struct buf* buf) {
    if (buf->data) {
        void* mapped_page = (unsigned char*)buf->data - buf->offset;
        kunmap(mapped_page);
    }

    struct inode* inode = buf->inode;
    slab_free(&buf_slab, buf);
    inode_unlock(inode);
    inode_unref(inode);
}
