#pragma once

#define PAGE_SIZE 4096

#define KERNEL_VIRT_ADDR 0xc0000000
#define KERNEL_PDE_IDX (KERNEL_VIRT_ADDR >> 22)

// Page is mapped
#define PTE_PRESENT 0x1

// Page may be written
#define PTE_WRITE 0x2

// Page may be accessed from userland
#define PTE_USER 0x4

// Page Attribute Table bit
// Used to enable write-combining caching.
#define PTE_PAT 0x80

// Page is global (not flushed from TLB on context switch)
#define PTE_GLOBAL 0x100

#define X86_PF_PROT 0x1
#define X86_PF_WRITE 0x2
#define X86_PF_USER 0x4
#define X86_PF_RSVD 0x8
#define X86_PF_INSTR 0x10

#ifndef ASM_FILE

#include <common/extra.h>
#include <kernel/api/sys/types.h>
#include <kernel/lock.h>

extern struct page_directory* kernel_page_directory;

typedef struct multiboot_info multiboot_info_t;

static inline bool is_user_address(const void* addr) {
    return addr && (uintptr_t)addr < KERNEL_VIRT_ADDR;
}

static inline bool is_user_range(const void* addr, size_t size) {
    if (!is_user_address(addr))
        return false;
    uintptr_t end = (uintptr_t)addr + size;
    return (uintptr_t)addr <= end && end <= KERNEL_VIRT_ADDR;
}

static inline bool is_kernel_address(const void* addr) {
    return addr && (uintptr_t)addr >= KERNEL_VIRT_ADDR;
}

static inline bool is_kernel_range(const void* addr, size_t size) {
    return is_kernel_address(addr) && (uintptr_t)addr <= (uintptr_t)addr + size;
}

void memory_init(const multiboot_info_t*);

struct memory_stats {
    size_t total_kibibytes;
    size_t free_kibibytes;
    size_t committed_kibibytes;
};

void memory_get_stats(struct memory_stats* out_stats);

#define PAGE_RESERVED 0x1
#define PAGE_ALLOCATED 0x2
#define PAGE_DIRTY 0x4

struct page {
    size_t offset;
    unsigned flags;    // PAGE_*
    struct page* next; // offset < next->offset
};

struct page* page_get(size_t pfn);
size_t page_to_pfn(const struct page*);

// Commits pages without allocating them.
NODISCARD bool page_commit(size_t n);

void page_uncommit(size_t n);

// Commits and allocates a page.
struct page* page_alloc(void);

// Returns the page frame number of the allocated page.
ssize_t page_alloc_raw(void);

// Allocates a page without committing it. At least one page should have been
// committed before calling this function.
struct page* page_alloc_committed(void);

// Frees and uncommits a page.
void page_free(struct page*);
void page_free_raw(size_t pfn);

// Returns a page from the list of pages. Returns NULL if the page is not found.
struct page* pages_get(struct page*, size_t offset);

// Allocates a page, inserting it into the list of pages.
NODISCARD struct page* pages_alloc_at(struct page**, size_t offset);

// Splits the pages into two at the offset.
// Returns the pages >= offset.
// Returns NULL if the offset is larger than the last page.
NODISCARD struct page* pages_split_off(struct page**, size_t offset);

// Frees a page, removing it from the list of pages.
void pages_free(struct page**, struct page*);

// Truncates the pages, freeing >= offset.
void pages_truncate(struct page**, size_t offset);

// Frees all the pages.
void pages_clear(struct page**);

void* kmalloc(size_t);
void* kaligned_alloc(size_t alignment, size_t);
void* krealloc(void*, size_t new_size);
void kfree(void*);

char* kstrdup(const char*);
char* kstrndup(const char*, size_t n);

void* phys_map(uintptr_t phys_addr, size_t size, unsigned vm_flags);
void phys_unmap(void*);

uintptr_t virt_to_phys(void*);

// Maps the pages to the virtual address.
NODISCARD int page_table_map(uintptr_t virt_addr, size_t pfn, size_t npages,
                             uint16_t flags);

// Maps the page to the virtual address. Only the TLB of the current CPU is
// flushed.
NODISCARD int page_table_map_local(uintptr_t virt_addr, size_t pfn,
                                   uint16_t flags);

// Unmaps the pages at the virtual address.
void page_table_unmap(uintptr_t virt_addr, size_t npages);

// Unmaps the page at the virtual address. Only the TLB of the current CPU is
// flushed.
void page_table_unmap_local(uintptr_t virt_addr);

void page_directory_switch(struct page_directory*);

#define MAX_NUM_KMAPS_PER_TASK 4

struct kmap_ctrl {
    size_t num_mapped;
    uintptr_t phys_addrs[MAX_NUM_KMAPS_PER_TASK];
};

// Maps a physical page to the kernel virtual address space.
// MAX_NUM_KMAPS_PER_TASK pages can be mapped at the same time for each task.
NODISCARD void* kmap(uintptr_t phys_addr);

NODISCARD void* kmap_page(struct page*);

// Unmaps the kmapped virtual address.
// kunmap must be called in the reverse order of kmap.
void kunmap(void* virt_addr);

// Should be called on context switch with the kmap_ctrl of the new task.
void kmap_switch(struct kmap_ctrl*);

struct slab_cache {
    struct mutex lock;
    size_t obj_size;
    struct slab_obj* free_list;
};

void slab_cache_init(struct slab_cache*, size_t obj_size);
void* slab_cache_alloc(struct slab_cache*);
void slab_cache_free(struct slab_cache*, void*);

#endif
