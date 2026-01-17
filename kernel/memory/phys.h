#pragma once

#include <common/tree.h>
#include <kernel/api/sys/types.h>
#include <kernel/arch/memory.h>

void phys_range_add_available(phys_addr_t start, size_t size);
void phys_range_add_reserved(const char* type, phys_addr_t start, size_t size);

#define PAGE_ALLOCATED 0x1 // Page is currently allocated
#define PAGE_DIRTY 0x2     // Page has been modified since the last writeback

struct page {
    size_t index;
    unsigned flags; // PAGE_*
    struct tree_node tree_node;
};

// The page filled with zeros.
extern struct page* zero_page;

struct page* page_get(size_t pfn);
size_t page_to_pfn(const struct page*);

struct page* page_alloc(void);

// Returns the page frame number of the allocated page.
ssize_t page_alloc_raw(void);

void page_free(struct page*);
void page_free_raw(size_t pfn);

void page_fill(struct page*, unsigned char value, size_t offset, size_t nbytes);
void page_copy(struct page* dest, struct page* src);
void page_copy_from_buffer(struct page* dest, const void* src, size_t offset,
                           size_t nbytes);
void page_copy_to_buffer(struct page* src, void* dest, size_t offset,
                         size_t nbytes);

// Returns the first page in the tree.
struct page* pages_first(const struct tree*);

// Returns the next page in the tree.
struct page* pages_next(const struct page*);

// Returns a page from the tree. Returns NULL if the page is not found.
struct page* pages_get(const struct tree*, size_t index);

// Allocates a page, inserting it into the tree.
NODISCARD struct page* pages_alloc_at(struct tree*, size_t index);

// Splits the page tree into two at the given index.
// Pages >= index are moved from src to dst, but with their indices adjusted
// to start from 0.
// If the index is larger than the last page in src, this is a no-op.
// Panics if there are duplicate page indices in dst.
void pages_split_off(struct tree* src, struct tree* dst, size_t index);

// Removes and frees all pages with indices >= index.
// Returns whether any pages were freed.
bool pages_truncate(struct tree*, size_t index);

// Frees all the pages.
void pages_clear(struct tree*);
