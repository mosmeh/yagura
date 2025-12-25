#include "private.h"
#include <common/limits.h>
#include <common/stdlib.h>
#include <common/string.h>
#include <kernel/kmsg.h>
#include <kernel/memory/phys.h>
#include <kernel/memory/vm.h>
#include <kernel/system.h>

struct phys_range {
    size_t pfn_start;
    size_t pfn_end;
    const char* type;
    bool is_available;
    size_t num_bump_allocated_pages;
};

static int phys_range_cmp(const void* a, const void* b) {
    const struct phys_range* ra = a;
    const struct phys_range* rb = b;
    if (ra->pfn_start < rb->pfn_start)
        return -1;
    if (ra->pfn_start > rb->pfn_start)
        return 1;
    if (ra->pfn_end < rb->pfn_end)
        return -1;
    if (ra->pfn_end > rb->pfn_end)
        return 1;
    return 0;
}

static struct phys_range phys_ranges[128];
static size_t num_phys_ranges;

static struct phys_range* alloc_range(void) {
    for (size_t i = 0; i < num_phys_ranges; ++i) {
        struct phys_range* r = &phys_ranges[i];
        if (r->pfn_start >= r->pfn_end) {
            // Reuse this slot
            return r;
        }
    }
    if (num_phys_ranges >= ARRAY_SIZE(phys_ranges))
        return NULL;
    return &phys_ranges[num_phys_ranges++];
}

void phys_range_add_available(phys_addr_t start, size_t size) {
    size_t pfn_start = DIV_CEIL(start, PAGE_SIZE);
    size_t pfn_end = (start + size) >> PAGE_SHIFT;
    if (pfn_end <= pfn_start) // size is 0 or overflow
        return;

    // Exclude reserved parts from the new available range
    for (size_t i = 0; i < num_phys_ranges; ++i) {
        struct phys_range* r = &phys_ranges[i];
        if (pfn_end <= r->pfn_start || r->pfn_end <= pfn_start ||
            r->is_available)
            continue;
        if (r->pfn_start <= pfn_start && pfn_end <= r->pfn_end) {
            // The entire range is reserved
            return;
        }
        if (pfn_start <= r->pfn_start && r->pfn_end <= pfn_end) {
            // Overlaps in the middle
            phys_range_add_available(pfn_start << PAGE_SHIFT,
                                     (r->pfn_start - pfn_start) << PAGE_SHIFT);
            phys_range_add_available(r->pfn_end << PAGE_SHIFT,
                                     (pfn_end - r->pfn_end) << PAGE_SHIFT);
            return;
        }
        if (r->pfn_start < pfn_end && pfn_end < r->pfn_end) {
            // Overlaps at the start
            pfn_start = r->pfn_end;
        } else if (r->pfn_start < pfn_start && pfn_start < r->pfn_end) {
            // Overlaps at the end
            pfn_end = r->pfn_start;
        }
    }

    struct phys_range* range = alloc_range();
    if (!range)
        return;
    *range = (struct phys_range){
        .pfn_start = pfn_start,
        .pfn_end = pfn_end,
        .type = "available",
        .is_available = true,
    };
}

void phys_range_add_reserved(const char* type, phys_addr_t start, size_t size) {
    size_t pfn_start = start >> PAGE_SHIFT;
    size_t pfn_end = DIV_CEIL(start + size, PAGE_SIZE);
    if (pfn_end <= pfn_start) // size is 0 or overflow
        return;

    // Exclude overlapping parts from existing available ranges
    for (size_t i = 0; i < num_phys_ranges; ++i) {
        struct phys_range* r = &phys_ranges[i];
        if (pfn_end <= r->pfn_start || r->pfn_end <= pfn_start ||
            !r->is_available)
            continue;
        if (r->pfn_start <= pfn_start && pfn_end <= r->pfn_end) {
            // Overlaps in the middle
            r->pfn_end = pfn_start;
            phys_range_add_available(pfn_end << PAGE_SHIFT,
                                     (r->pfn_end - pfn_end) << PAGE_SHIFT);
        } else if (pfn_start <= r->pfn_start && r->pfn_end <= pfn_end) {
            // The entire range is reserved
            r->pfn_end = r->pfn_start; // Mark as unused
        } else if (r->pfn_start < pfn_end && pfn_end < r->pfn_end) {
            // Overlaps at the start
            r->pfn_start = pfn_end;
        } else if (r->pfn_start < pfn_start && pfn_start < r->pfn_end) {
            // Overlaps at the end
            r->pfn_end = pfn_start;
        }
    }

    struct phys_range* range = alloc_range();
    if (!range)
        return;
    *range = (struct phys_range){
        .pfn_start = pfn_start,
        .pfn_end = pfn_end,
        .type = type,
        .is_available = false,
    };
}

#define BITMAP_INDEX(i) ((i) / (LONG_WIDTH))
#define BITMAP_MASK(i) (1UL << ((i) & (LONG_WIDTH - 1)))

static size_t available_pfn_end;       // One past the last allocatable pfn
static _Atomic(unsigned long)* bitmap; // bit unset = allocated, set = free
static _Atomic(size_t) cached_free_index;

// Returns the previous state of the bit.
static bool bitmap_set(size_t i) {
    ASSERT(i < available_pfn_end);
    unsigned long prev =
        atomic_fetch_or(&bitmap[BITMAP_INDEX(i)], BITMAP_MASK(i));
    return prev & BITMAP_MASK(i);
}

static size_t bitmap_get_free(void) {
    size_t bitmap_len = DIV_CEIL(available_pfn_end, LONG_WIDTH);
    size_t i = cached_free_index;
    for (size_t offset = 0; offset < bitmap_len; ++offset) {
        for (;;) {
            unsigned long v = bitmap[i];
            int b = __builtin_ffsl(v);
            if (b == 0) // v == 0
                break;
            unsigned long new_v = v & ~BITMAP_MASK(b - 1);
            if (atomic_compare_exchange_weak(&bitmap[i], &v, new_v)) {
                cached_free_index = i;
                return i * LONG_WIDTH + (b - 1);
            }
        }
        i = (i + 1) % bitmap_len;
    }
    UNREACHABLE();
}

static struct page* pages;
static size_t total_pages;
static _Atomic(size_t) free_pages;

struct page* zero_page;

void phys_init(void) {
    ASSERT(KERNEL_IMAGE_START < (uintptr_t)kernel_end);
    ASSERT((uintptr_t)kernel_end <= KERNEL_IMAGE_END);

    phys_range_add_reserved("kernel", 0,
                            (uintptr_t)kernel_end - KERNEL_IMAGE_START);

    qsort(phys_ranges, num_phys_ranges, sizeof(struct phys_range),
          phys_range_cmp);

    for (size_t i = 0; i < num_phys_ranges; ++i) {
        struct phys_range* r = &phys_ranges[i];
        if (r->pfn_start >= r->pfn_end)
            continue;

        kprintf("phys: %#018zx - %#018zx | %10zu MiB | %s\n",
                r->pfn_start << PAGE_SHIFT, r->pfn_end << PAGE_SHIFT,
                ((r->pfn_end - r->pfn_start) << PAGE_SHIFT) / 0x100000,
                r->type);

        if (!r->is_available)
            continue;

        available_pfn_end = MAX(available_pfn_end, r->pfn_end);
        free_pages += r->pfn_end - r->pfn_start;
    }

    ssize_t zero_page_pfn = page_alloc_raw();
    ASSERT_OK(zero_page_pfn);
    void* kaddr = kmap(zero_page_pfn << PAGE_SHIFT);
    memset(kaddr, 0, PAGE_SIZE);
    kunmap(kaddr);

    size_t bitmap_npages = DIV_CEIL(available_pfn_end, CHAR_BIT * PAGE_SIZE);
    uintptr_t bitmap_end = PAGE_ATLAS_START + (bitmap_npages << PAGE_SHIFT);
    ASSERT(bitmap_end < PAGE_ATLAS_END);

    // Initialize the bitmap to all zero (reserved).
    for (size_t i = 0; i < bitmap_npages; ++i) {
        uintptr_t virt_addr = PAGE_ATLAS_START + (i << PAGE_SHIFT);
        ASSERT_OK(pagemap_map_local(kernel_pagemap, virt_addr, zero_page_pfn,
                                    VM_READ));
    }

    // Allocate the bitmap pages for available pages.
    for (size_t i = 0; i < num_phys_ranges; ++i) {
        struct phys_range* r = &phys_ranges[i];
        if (r->pfn_start >= r->pfn_end || !r->is_available)
            continue;

        size_t start_offset = ROUND_DOWN(r->pfn_start / CHAR_BIT, PAGE_SIZE);
        size_t end_offset = ROUND_UP(DIV_CEIL(r->pfn_end, CHAR_BIT), PAGE_SIZE);

        uintptr_t start_addr = PAGE_ATLAS_START + start_offset;
        uintptr_t end_addr = PAGE_ATLAS_START + end_offset;

        for (uintptr_t virt_addr = start_addr; virt_addr < end_addr;
             virt_addr += PAGE_SIZE) {
            ssize_t pfn = page_alloc_raw();
            ASSERT_OK(pfn);
            ASSERT_OK(pagemap_map_local(kernel_pagemap, virt_addr, pfn,
                                        VM_READ | VM_WRITE));
        }

        memset((void*)start_addr, 0, end_addr - start_addr);
    }

    bitmap = (void*)PAGE_ATLAS_START;

    for (size_t i = 0; i < num_phys_ranges; ++i) {
        struct phys_range* r = &phys_ranges[i];
        if (r->pfn_start >= r->pfn_end || !r->is_available)
            continue;

        // Bump-allocated pages are kept marked as allocated in the bitmap.
        size_t pfn_start = r->pfn_start + r->num_bump_allocated_pages;
        for (size_t pfn = pfn_start; pfn < r->pfn_end; ++pfn)
            ASSERT(!bitmap_set(pfn));
    }

    // We can now use the bitmap for page allocation.

    pages = (void*)bitmap_end;
    ASSERT(pages + available_pfn_end <= (const struct page*)PAGE_ATLAS_END);

    // Map pages for the struct page array.
    // Pages corresponding to reserved ranges are left unmapped.
    for (size_t i = 0; i < num_phys_ranges; ++i) {
        struct phys_range* r = &phys_ranges[i];
        if (r->pfn_start >= r->pfn_end || !r->is_available)
            continue;

        size_t pfn_start = r->pfn_start + r->num_bump_allocated_pages;

        size_t start_offset =
            ROUND_DOWN(pfn_start * sizeof(struct page), PAGE_SIZE);
        size_t end_offset =
            ROUND_UP(r->pfn_end * sizeof(struct page), PAGE_SIZE);

        uintptr_t start_addr = (uintptr_t)pages + start_offset;
        uintptr_t end_addr = (uintptr_t)pages + end_offset;

        for (uintptr_t virt_addr = start_addr; virt_addr < end_addr;
             virt_addr += PAGE_SIZE) {
            ssize_t pfn = page_alloc_raw();
            ASSERT_OK(pfn);
            ASSERT_OK(pagemap_map_local(kernel_pagemap, virt_addr, pfn,
                                        VM_READ | VM_WRITE));
        }

        for (size_t pfn = pfn_start; pfn < r->pfn_end; ++pfn)
            *page_get(pfn) = (struct page){0};
    }

    total_pages = free_pages;
    kprintf("phys: %zu pages (%zu MiB) available\n", total_pages,
            (total_pages << PAGE_SHIFT) / 0x100000);

    zero_page = page_get(zero_page_pfn);
}

struct page* page_get(size_t pfn) {
    struct page* page = pages + pfn;
    ASSERT(page < (const struct page*)PAGE_ATLAS_END);
    return page;
}

size_t page_to_pfn(const struct page* page) {
    ASSERT(page);
    ASSERT(page >= pages);
    ASSERT(page < (const struct page*)PAGE_ATLAS_END);
    return page - pages;
}

phys_addr_t page_to_phys(const struct page* page) {
    return (phys_addr_t)page_to_pfn(page) << PAGE_SHIFT;
}

struct page* page_alloc(void) {
    ssize_t pfn = page_alloc_raw();
    if (IS_ERR(pfn))
        return ERR_PTR(pfn);
    struct page* page = page_get(pfn);
    ASSERT(!page->flags);
    *page = (struct page){
        .flags = PAGE_ALLOCATED,
    };
    return page;
}

ssize_t page_alloc_raw(void) {
    for (;;) {
        size_t n = free_pages;
        if (n == 0)
            return -ENOMEM;
        if (atomic_compare_exchange_weak(&free_pages, &n, n - 1))
            break;
    }

    if (bitmap)
        return bitmap_get_free();

    // Before the bitmap is initialized, use simple bump allocation.
    for (size_t i = 0; i < num_phys_ranges; ++i) {
        struct phys_range* r = &phys_ranges[i];
        if (r->pfn_start >= r->pfn_end || !r->is_available)
            continue;

        size_t pfn = r->pfn_start + r->num_bump_allocated_pages;
        if (pfn < r->pfn_end) {
            r->num_bump_allocated_pages++;
            return pfn;
        }
    }
    UNREACHABLE();
}

void page_free(struct page* page) {
    if (!page)
        return;
    ASSERT(page->flags & PAGE_ALLOCATED);
    *page = (struct page){0};
    page_free_raw(page_to_pfn(page));
}

void page_free_raw(size_t pfn) {
    ASSERT(!bitmap_set(pfn));
    ++free_pages;
}

void page_fill(struct page* page, unsigned char value, size_t offset,
               size_t nbytes) {
    ASSERT(offset + nbytes <= PAGE_SIZE);
    unsigned char* mapped_page = kmap_page(page);
    memset(mapped_page + offset, value, nbytes);
    kunmap(mapped_page);
}

void page_copy(struct page* dest, struct page* src) {
    void* src_mapped = kmap_page(src);
    page_copy_from_buffer(dest, src_mapped, 0, PAGE_SIZE);
    kunmap(src_mapped);
}

void page_copy_from_buffer(struct page* dest, const void* src, size_t offset,
                           size_t nbytes) {
    ASSERT(offset + nbytes <= PAGE_SIZE);
    unsigned char* dest_mapped = kmap_page(dest);
    memcpy(dest_mapped + offset, src, nbytes);
    kunmap(dest_mapped);
}

void page_copy_to_buffer(struct page* src, void* dest, size_t offset,
                         size_t nbytes) {
    ASSERT(offset + nbytes <= PAGE_SIZE);
    unsigned char* src_mapped = kmap_page(src);
    memcpy(dest, src_mapped + offset, nbytes);
    kunmap(src_mapped);
}

struct page* pages_first(const struct tree* tree) {
    struct tree_node* node = tree_first(tree);
    if (!node)
        return NULL;
    return CONTAINER_OF(node, struct page, tree_node);
}

struct page* pages_next(const struct page* page) {
    struct tree_node* node = tree_next(&page->tree_node);
    if (!node)
        return NULL;
    return CONTAINER_OF(node, struct page, tree_node);
}

struct page* pages_get(const struct tree* tree, size_t index) {
    struct tree_node* node = tree->root;
    while (node) {
        struct page* page = CONTAINER_OF(node, struct page, tree_node);
        if (index < page->index)
            node = node->left;
        else if (index > page->index)
            node = node->right;
        else
            return page;
    }
    return NULL;
}

struct page* pages_alloc_at(struct tree* tree, size_t index) {
    struct tree_node** new_node = &tree->root;
    struct tree_node* parent = NULL;
    while (*new_node) {
        parent = *new_node;
        struct page* page = CONTAINER_OF(parent, struct page, tree_node);
        if (index < page->index)
            new_node = &parent->left;
        else if (index > page->index)
            new_node = &parent->right;
        else
            return ERR_PTR(-EEXIST);
    }

    struct page* page = page_alloc();
    if (IS_ERR(ASSERT(page)))
        return page;
    page->index = index;

    *new_node = &page->tree_node;
    tree_insert(tree, parent, *new_node);

    return page;
}

void pages_split_off(struct tree* src, struct tree* dst, size_t index) {
    for (;;) {
        struct tree_node* node = tree_last(src);
        if (!node)
            break;
        struct page* page = CONTAINER_OF(node, struct page, tree_node);
        if (page->index < index)
            break;
        tree_remove(src, node);
        page->index -= index;

        struct tree_node** new_node = &dst->root;
        struct tree_node* parent = NULL;
        while (*new_node) {
            parent = *new_node;
            struct page* dst_page =
                CONTAINER_OF(parent, struct page, tree_node);
            if (page->index < dst_page->index)
                new_node = &parent->left;
            else if (page->index > dst_page->index)
                new_node = &parent->right;
            else
                PANIC("Duplicate page index");
        }
        *new_node = node;
        tree_insert(dst, parent, *new_node);
    }
}

bool pages_truncate(struct tree* tree, size_t index) {
    bool truncated = false;
    for (;;) {
        struct tree_node* node = tree_last(tree);
        if (!node)
            break;
        struct page* page = CONTAINER_OF(node, struct page, tree_node);
        if (page->index < index)
            break;
        tree_remove(tree, node);
        page_free(page);
        truncated = true;
    }
    return truncated;
}

void pages_clear(struct tree* tree) {
    for (;;) {
        struct tree_node* node = tree->root;
        if (!node)
            break;
        tree_remove(tree, node);
        struct page* page = CONTAINER_OF(node, struct page, tree_node);
        page_free(page);
    }
}

void memory_get_stats(struct memory_stats* out_stats) {
    *out_stats = (struct memory_stats){
        .total_kibibytes = (total_pages << PAGE_SHIFT) / 1024,
        .free_kibibytes = (free_pages << PAGE_SHIFT) / 1024,
    };
}
