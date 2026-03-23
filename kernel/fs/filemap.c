#include "private.h"
#include <common/integer.h>
#include <common/string.h>
#include <kernel/fs/inode.h>
#include <kernel/memory/phys.h>

static struct slab filemap_slab;

void filemap_init(void) {
    SLAB_INIT_FOR_TYPE(&filemap_slab, "filemap", struct filemap);
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

struct page* filemap_ensure_page(struct filemap* filemap, size_t index) {
    struct inode* inode = filemap->inode;
    ASSERT(inode_is_locked_by_current(inode));
    ASSERT_PTR(inode->iops->read);

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

    struct page* page FREE(page) = ASSERT(page_alloc());
    if (IS_ERR(page))
        return page;
    page->index = index;

    if (((uint64_t)index << PAGE_SHIFT) < inode->size) {
        int rc = inode->iops->read(inode, page, index);
        if (IS_ERR(rc))
            return ERR_PTR(rc);
    } else {
        page_fill(page, 0, 0, PAGE_SIZE);
    }

    *new_node = &page->tree_node;
    page_ref(page);
    tree_insert(&filemap->pages, parent, *new_node);

    return TAKE_PTR(page);
}

NODISCARD static int writeback_page(struct filemap* filemap,
                                    struct page* page) {
    struct inode* inode = filemap->inode;
    ASSERT(inode_is_locked_by_current(inode));
    ASSERT(((uint64_t)page->index << PAGE_SHIFT) < inode->size);
    ASSERT_PTR(inode->iops->write);

    if (!(page->flags & PAGE_DIRTY))
        return 0;

    // Invalidate the mappings to detect writes to the page again.
    // If another task attempts to write to this page during the writeback,
    // the page fault handling will be blocked until the writeback is done
    // because we hold the inode lock.
    int rc = vm_obj_invalidate_mappings(&inode->vm_obj, page->index, 1);
    if (IS_ERR(rc))
        return rc;

    rc = inode->iops->write(inode, page, page->index);
    if (IS_ERR(rc))
        return rc;

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

int filemap_sync(struct filemap* filemap, size_t start, size_t end) {
    struct inode* inode = filemap->inode;
    ASSERT(inode_is_locked_by_current(inode));
    if (start > end)
        return -EINVAL;
    if (end == start)
        return 0;
    if (!(inode->flags & INODE_DIRTY))
        return 0;
    if (!inode->iops->write)
        return -EINVAL;

    end = MIN(end, DIV_CEIL(inode->size, PAGE_SIZE));

    int rc = 0;
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
            struct page* next = pages_next(page);
            page_unref(page);
            page = next;
        }
    }
    if (inode->iops->sync) {
        int fsync_rc = inode->iops->sync(inode);
        if (IS_OK(rc))
            rc = fsync_rc;
    }
    if (IS_ERR(rc))
        return rc;

    {
        struct page* page FREE(page) = pages_first(&filemap->pages);
        while (page) {
            if (page->flags & PAGE_DIRTY)
                return 0;
            struct page* next = pages_next(page);
            page_unref(page);
            page = next;
        }
    }
    inode->flags &= ~INODE_DIRTY;
    return 0;
}

int filemap_truncate(struct filemap* filemap, uint64_t length) {
    struct inode* inode = filemap->inode;
    ASSERT(inode_is_locked_by_current(inode));

    size_t end = DIV_CEIL(length, PAGE_SIZE);

    bool truncated = pages_truncate(&filemap->pages, end);
    size_t page_offset = length % PAGE_SIZE;
    if (page_offset > 0) {
        struct page* page FREE(page) = pages_get(&filemap->pages, end - 1);
        if (page) {
            page_fill(page, 0, page_offset, PAGE_SIZE - page_offset);
            page->flags |= PAGE_DIRTY;
        }
    }

    if (truncated)
        return vm_obj_invalidate_mappings(&inode->vm_obj, end, SIZE_MAX - end);

    return 0;
}
