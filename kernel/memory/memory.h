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
#include <kernel/lock.h>

extern struct page_directory* kernel_page_directory;

typedef struct multiboot_info multiboot_info_t;
struct vm_obj;

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

struct page_set {
    struct page* pages;
};

struct page* page_set_first(struct page_set*);
struct page* page_set_get(struct page_set*, size_t offset);
struct page* page_set_alloc_at(struct page_set*, size_t offset);
void page_set_free(struct page_set*, struct page*);
void page_set_clear(struct page_set*);

void* kmalloc(size_t);
void* kaligned_alloc(size_t alignment, size_t);
void* krealloc(void*, size_t new_size);
void kfree(void*);

char* kstrdup(const char*);
char* kstrndup(const char*, size_t n);

void* phys_map(uintptr_t phys_addr, size_t size, unsigned vm_flags);
void phys_unmap(void*);

uintptr_t virt_to_phys(void*);

struct vm_ops {
    void (*destroy_obj)(struct vm_obj*);
    struct page* (*populate)(struct vm_obj*, size_t offset,
                             uint32_t error_code);
    void (*on_write)(struct vm_obj*, struct page*);
};

struct vm_obj {
    const struct vm_ops* vm_ops;
    struct page_set shared_pages;
    struct vm_region* shared_regions;
    struct spinlock lock;
    atomic_size_t ref_count;
};

void vm_obj_ref(struct vm_obj*);
void vm_obj_unref(struct vm_obj*);

struct vm_obj* anon_create(void);
struct vm_obj* phys_create(uintptr_t phys_addr, size_t npages);

struct vm {
    size_t start; // Start virtual address / PAGE_SIZE (inclusive)
    size_t end;   // End virtual address / PAGE_SIZE (exclusive)
    struct page_directory* page_directory;
    struct vm_region* regions;
    struct spinlock lock;
    atomic_size_t ref_count;
};

// Region may be read
#define VM_READ 0x1

// Region may be written
#define VM_WRITE 0x2

// Region may be accessed from userland
#define VM_USER 0x4

// vm_obj is shared with other regions
#define VM_SHARED 0x8

// Write-combining is enabled for the region
#define VM_WC 0x10

struct vm_region {
    struct vm* vm;
    size_t start;   // Start virtual address / PAGE_SIZE (inclusive)
    size_t end;     // End virtual address / PAGE_SIZE (exclusive)
    size_t offset;  // Offset into the obj (in pages)
    unsigned flags; // VM_*
    struct vm_obj* obj;
    struct page_set private_pages;
    struct vm_region* prev;        // prev->end <= start
    struct vm_region* next;        // end <= next->start
    struct vm_region* shared_next; // obj == shared_next->obj
};

extern struct vm* kernel_vm;

struct vm* vm_create(void* start, void* end);
void vm_ref(struct vm*);
void vm_unref(struct vm*);

// Switches to the virtual memory space. Returns the previous vm.
struct vm* vm_enter(struct vm*);

// Clones the virtual memory space.
struct vm* vm_clone(struct vm*);

NODISCARD bool vm_handle_page_fault(void* virt_addr, uint32_t error_code);

// Finds the region that contains the given address.
// Returns NULL if no region contains the address.
struct vm_region* vm_find(struct vm*, void* virt_addr);

// Allocates a virtual memory region at arbitrary address.
NODISCARD struct vm_region* vm_alloc(struct vm*, size_t npages);

// Allocates a virtual memory region at a specific virtual address range.
NODISCARD struct vm_region* vm_alloc_at(struct vm*, void* virt_addr,
                                        size_t npages);

// Sets the vm_obj and offset into the vm_obj.
// Panics if the region already has a vm_obj.
void vm_region_set_obj(struct vm_region*, struct vm_obj*, size_t offset);

// Returns the start virtual address of the region.
void* vm_region_to_virt(struct vm_region*);

// Resizes a virtual memory region.
NODISCARD int vm_region_resize(struct vm_region*, size_t new_npages);

// Sets the flags of a virtual memory region.
// mask is a bitmask that specifies which flags are changed.
// If only a part of the region is modified, the region is split.
NODISCARD int vm_region_set_flags(struct vm_region*, size_t offset,
                                  size_t npages, unsigned flags, unsigned mask);

// Frees a virtual memory region.
// If only a part of the region is freed, the region is shrunk or split.
NODISCARD int vm_region_free(struct vm_region*, size_t offset, size_t npages);

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

static inline uint16_t vm_flags_to_pte_flags(unsigned vm_flags) {
    uint16_t pte_flags = (vm_flags & VM_USER) ? PTE_USER : PTE_GLOBAL;
    if (vm_flags & VM_WRITE)
        pte_flags |= PTE_WRITE;
    if (vm_flags & VM_USER)
        pte_flags |= PTE_USER;
    if (vm_flags & VM_WC)
        pte_flags |= PTE_PAT;
    return pte_flags;
}

#define MAX_NUM_KMAPS_PER_TASK 2

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
    struct spinlock lock;
    size_t obj_size;
    struct slab_obj* free_list;
};

void slab_cache_init(struct slab_cache*, size_t obj_size);
void* slab_cache_alloc(struct slab_cache*);
void slab_cache_free(struct slab_cache*, void*);

#endif
