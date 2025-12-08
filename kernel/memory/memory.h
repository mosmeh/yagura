#pragma once

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)

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
#include <kernel/resource.h>

struct file;
struct vec;
typedef struct multiboot_info multiboot_info_t;

extern struct page_directory* kernel_page_directory;

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
};

void memory_get_stats(struct memory_stats* out_stats);

#define PAGE_RESERVED 0x1  // Page is reserved and cannot be allocated
#define PAGE_ALLOCATED 0x2 // Page is currently allocated
#define PAGE_DIRTY 0x4     // Page has been modified since the last writeback

struct page {
    size_t index;
    unsigned flags;    // PAGE_*
    struct page* next; // index < next->index
};

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

// Returns a page from the list of pages. Returns NULL if the page is not found.
struct page* pages_get(struct page*, size_t index);

// Allocates a page, inserting it into the list of pages.
NODISCARD struct page* pages_alloc_at(struct page**, size_t index);

// Splits the pages into two at the index.
// Returns the pages >= index.
// Returns NULL if the index is larger than the last page.
NODISCARD struct page* pages_split_off(struct page**, size_t index);

// Frees a page, removing it from the list of pages.
void pages_free(struct page**, struct page*);

// Truncates the pages, freeing >= index.
// Returns whether any pages were freed.
bool pages_truncate(struct page**, size_t index);

// Frees all the pages.
void pages_clear(struct page**);

void* kmalloc(size_t);
void* kaligned_alloc(size_t alignment, size_t);
void* krealloc(void*, size_t new_size);
void kfree(void*);

DEFINE_FREE(kfree, void*, kfree)

char* kstrdup(const char*);
char* kstrndup(const char*, size_t n);

// Translates virtual address to physical address.
// Panics if the address is not mapped.
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

#define MAX_NUM_KMAPS_PER_CPU 4

struct kmap_ctrl {
    size_t num_mapped;
    bool pushed_cli;
    uintptr_t phys_addrs[MAX_NUM_KMAPS_PER_CPU];
};

// Maps a physical page to the kernel virtual address space.
// MAX_NUM_KMAPS_PER_CPU pages can be mapped at the same time for each CPU.
NODISCARD void* kmap(uintptr_t phys_addr);

NODISCARD void* kmap_page(struct page*);

// Unmaps the kmapped virtual address.
// kunmap must be called in the reverse order of kmap.
void kunmap(void* virt_addr);

struct slab {
    const char* name;
    size_t obj_size;        // Size of each object in bytes
    size_t total_objs;      // Total number of allocated objects
    size_t num_active_objs; // Number of objects currently in use
    struct slab_obj* free_list;
    struct mutex lock;
    struct slab* next;
};

void slab_init(struct slab*, const char* name, size_t obj_size);
void* slab_alloc(struct slab*);
void slab_free(struct slab*, void*);

int proc_print_slabinfo(struct file*, struct vec*);

#endif
