#include "private.h"
#include <common/integer.h>
#include <common/string.h>
#include <kernel/fs/inode.h>
#include <kernel/memory/phys.h>

static struct slab filemap_slab;

void filemap_init(void) {
    slab_init(&filemap_slab, "filemap", sizeof(struct filemap));
}

struct filemap* filemap_create(struct inode* inode) {
    struct filemap* filemap = ASSERT(slab_alloc(&filemap_slab));
    if (IS_ERR(filemap))
        return filemap;
    *filemap = (struct filemap){
        .inode = inode_ref(inode),
    };
    return filemap;
}

void filemap_destroy(struct filemap* filemap) {
    if (!filemap)
        return;
    pages_clear(&filemap->pages);
    slab_free(&filemap_slab, filemap);
}

NODISCARD static int populate_page(struct filemap* filemap, struct page* page) {
    struct inode* inode = filemap->inode;
    ASSERT(inode_is_locked_by_current(inode));
    ASSERT_PTR(inode->iops->pread);

    uint64_t byte_offset = (uint64_t)page->index << PAGE_SHIFT;

    unsigned char buf[PAGE_SIZE];
    unsigned char* dest = buf;
    size_t to_read = MIN(PAGE_SIZE, inode->size - byte_offset);
    while (to_read > 0) {
        ssize_t nread = inode->iops->pread(inode, dest, to_read, byte_offset);
        if (IS_ERR(nread))
            return nread;
        if (nread == 0) {
            memset(dest, 0, to_read);
            break;
        }
        dest += nread;
        to_read -= nread;
        byte_offset += nread;
    }
    page_copy_from_buffer(page, buf, 0, PAGE_SIZE);

    return 0;
}

struct page* filemap_ensure_page(struct filemap* filemap, size_t index,
                                 bool extend) {
    struct inode* inode = filemap->inode;
    ASSERT(inode_is_locked_by_current(inode));

    struct tree_node** new_node = &filemap->pages.root;
    struct tree_node* parent = NULL;
    while (*new_node) {
        parent = *new_node;
        struct page* page = CONTAINER_OF(parent, struct page, tree_node);
        if (index < page->index)
            new_node = &parent->left;
        else if (index > page->index)
            new_node = &parent->right;
        else
            return page_ref(page);
    }

    uint64_t byte_offset = (uint64_t)index << PAGE_SHIFT;
    if (byte_offset >= inode->size) {
        if (extend) {
            struct page* page = ASSERT(page_alloc());
            if (IS_ERR(page))
                return page;
            page->index = index;
            page_fill(page, 0, 0, PAGE_SIZE);
            *new_node = &page->tree_node;
            page_ref(page);
            tree_insert(&filemap->pages, parent, *new_node);
            return page;
        }
        return NULL;
    }

    struct page* page FREE(page) = ASSERT(page_alloc());
    if (IS_ERR(page))
        return page;
    page->index = index;

    int rc = populate_page(filemap, page);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    *new_node = &page->tree_node;
    page_ref(page);
    tree_insert(&filemap->pages, parent, *new_node);

    return TAKE_PTR(page);
}

NODISCARD static int writeback_page(struct filemap* filemap,
                                    struct page* page) {
    struct inode* inode = filemap->inode;
    ASSERT(inode_is_locked_by_current(inode));
    if (!(page->flags & PAGE_DIRTY))
        return 0;

    ASSERT_PTR(inode->iops->pwrite);

    // Invalidate the mappings to detect writes to the page again.
    // If another task attempts to write to this page during the writeback,
    // the page fault handling will be blocked until the writeback is done
    // because we hold the inode lock.
    int rc = vm_obj_invalidate_mappings(&inode->vm_obj, page->index, 1);
    if (IS_ERR(rc))
        return rc;

    uint64_t byte_offset = (uint64_t)page->index << PAGE_SHIFT;
    if (inode->size > byte_offset) {
        size_t to_write = MIN(PAGE_SIZE, inode->size - byte_offset);

        unsigned char page_buf[PAGE_SIZE];
        page_copy_to_buffer(page, page_buf, 0, to_write);

        const unsigned char* src = page_buf;
        while (to_write > 0) {
            ssize_t nwritten =
                inode->iops->pwrite(inode, src, to_write, byte_offset);
            if (IS_ERR(nwritten))
                return nwritten;
            ASSERT(nwritten > 0);
            src += nwritten;
            to_write -= nwritten;
            byte_offset += nwritten;
        }
    }

    page->flags &= ~PAGE_DIRTY;
    return 0;
}

static struct page* find_page_with_lower_bound(const struct filemap* filemap,
                                               size_t start) {
    struct tree_node* node = filemap->pages.root;
    struct page* result = NULL;
    while (node) {
        struct page* page = CONTAINER_OF(node, struct page, tree_node);
        if (start < page->index) {
            result = page;
            node = node->left;
        } else if (start > page->index) {
            node = node->right;
        } else {
            return page_ref(page);
        }
    }
    return result ? page_ref(result) : NULL;
}

NODISCARD int filemap_sync(struct filemap* filemap, size_t start, size_t end) {
    struct inode* inode = filemap->inode;
    ASSERT(inode_is_locked_by_current(inode));
    if (start > end)
        return -EINVAL;
    if (end == start)
        return 0;
    if (!(inode->flags & INODE_DIRTY))
        return 0;

    int rc = 0;
    size_t num_successful = 0;
    {
        struct page* page FREE(page) =
            find_page_with_lower_bound(filemap, start);
        if (page)
            ASSERT(page->index >= start);

        while (page) {
            if (end <= page->index)
                break;
            rc = writeback_page(filemap, page);
            if (IS_ERR(rc))
                break;
            ++num_successful;
            struct page* next = pages_next(page);
            page_unref(page);
            page = next;
        }
    }

    if (num_successful > 0 && inode->iops->sync) {
        int fsync_rc = inode->iops->sync(inode);
        if (IS_OK(rc))
            rc = fsync_rc;
    }

    bool has_any_dirty_pages = false;
    {
        struct page* page FREE(page) = pages_first(&filemap->pages);
        while (page) {
            if (page->flags & PAGE_DIRTY) {
                has_any_dirty_pages = true;
                break;
            }
            struct page* next = pages_next(page);
            page_unref(page);
            page = next;
        }
    }
    if (!has_any_dirty_pages)
        inode->flags &= ~INODE_DIRTY;

    return rc;
}

NODISCARD int filemap_truncate(struct filemap* filemap, uint64_t length) {
    struct inode* inode = filemap->inode;
    ASSERT(inode_is_locked_by_current(inode));

    size_t end = DIV_CEIL(length, PAGE_SIZE);

    bool truncated = pages_truncate(&filemap->pages, end);
    size_t page_offset = length % PAGE_SIZE;
    if (page_offset > 0) {
        struct page* page FREE(page) = pages_get(&filemap->pages, end - 1);
        if (page)
            page_fill(page, 0, page_offset, PAGE_SIZE - page_offset);
    }

    if (truncated)
        return vm_obj_invalidate_mappings(&inode->vm_obj, end, SIZE_MAX - end);

    return 0;
}
