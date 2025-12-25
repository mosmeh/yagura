#include "private.h"
#include <common/integer.h>
#include <common/string.h>
#include <kernel/device/device.h>
#include <kernel/memory/phys.h>

static struct slab filemap_slab;

void filemap_init(void) {
    slab_init(&filemap_slab, "filemap", sizeof(struct filemap));
}

struct filemap* filemap_create(struct inode* inode) {
    struct filemap* filemap = slab_alloc(&filemap_slab);
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
            return page;
    }

    uint64_t byte_offset = (uint64_t)index << PAGE_SHIFT;
    if (byte_offset >= inode->size) {
        if (extend) {
            struct page* page = page_alloc();
            if (IS_ERR(ASSERT(page)))
                return page;
            page->index = index;
            page_fill(page, 0, 0, PAGE_SIZE);
            *new_node = &page->tree_node;
            tree_insert(&filemap->pages, parent, *new_node);
            return page;
        }
        return NULL;
    }

    struct page* page = page_alloc();
    if (IS_ERR(ASSERT(page)))
        return page;
    page->index = index;

    ASSERT(inode->iops->read);
    int rc = inode->iops->read(inode, page, index);
    if (IS_ERR(rc)) {
        page_free(page);
        return ERR_PTR(rc);
    }

    *new_node = &page->tree_node;
    tree_insert(&filemap->pages, parent, *new_node);

    return page;
}

NODISCARD static int writeback_page(struct filemap* filemap,
                                    struct page* page) {
    struct inode* inode = filemap->inode;
    ASSERT(inode_is_locked_by_current(inode));
    if (!page->dirty)
        return 0;

    ASSERT(inode->iops->write);

    // Invalidate the mappings to detect writes to the page again.
    // If another task attempts to write to this page during the writeback,
    // the page fault handling will be blocked until the writeback is done
    // because we hold the inode lock.
    int rc = vm_obj_invalidate_mappings(&inode->vm_obj, page->index, 1);
    if (IS_ERR(rc))
        return rc;

    uint64_t byte_offset = (uint64_t)page->index << PAGE_SHIFT;
    if (inode->size > byte_offset) {
        int rc = inode->iops->write(inode, page, page->index);
        if (IS_ERR(rc))
            return rc;
    }

    page->dirty = 0;
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
            return page;
        }
    }
    return result;
}

int filemap_sync(struct filemap* filemap, size_t start, size_t end) {
    struct inode* inode = filemap->inode;
    ASSERT(inode_is_locked_by_current(inode));
    if (start > end)
        return -EINVAL;
    if (end == start)
        return 0;
    if (!(inode->flags & INODE_DIRTY))
        return 0;

    struct page* page = find_page_with_lower_bound(filemap, start);
    if (page)
        ASSERT(page->index >= start);

    int rc = 0;
    size_t num_successful = 0;
    for (; page; page = pages_next(page)) {
        if (end <= page->index)
            break;
        rc = writeback_page(filemap, page);
        if (IS_ERR(rc))
            break;
        ++num_successful;
    }

    if (num_successful > 0 && inode->iops->sync) {
        int fsync_rc = inode->iops->sync(inode);
        if (IS_OK(rc))
            rc = fsync_rc;
    }

    bool has_any_dirty_pages = false;
    for (page = pages_first(&filemap->pages); page; page = pages_next(page)) {
        if (page->dirty) {
            has_any_dirty_pages = true;
            break;
        }
    }
    if (!has_any_dirty_pages)
        inode->flags &= ~INODE_DIRTY;

    return rc;
}

int filemap_truncate(struct filemap* filemap, uint64_t length) {
    struct inode* inode = filemap->inode;
    ASSERT(inode_is_locked_by_current(inode));

    size_t end = DIV_CEIL(length, PAGE_SIZE);

    bool truncated = pages_truncate(&filemap->pages, end);
    size_t page_offset = length % PAGE_SIZE;
    if (page_offset > 0) {
        struct page* page = pages_get(&filemap->pages, end - 1);
        if (page)
            page_fill(page, 0, page_offset, PAGE_SIZE - page_offset);
    }

    if (truncated)
        return vm_obj_invalidate_mappings(&inode->vm_obj, end, SIZE_MAX);

    return 0;
}
