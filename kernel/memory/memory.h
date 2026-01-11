#pragma once

#include <kernel/arch/memory.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)

#ifndef __ASSEMBLER__

#include <common/macros.h>
#include <kernel/lock.h>
#include <kernel/resource.h>

struct file;
struct vec;
struct registers;
struct page;

static inline bool is_user_address(const void* addr) {
    return addr && USER_VIRT_START <= (uintptr_t)addr &&
           (uintptr_t)addr < USER_VIRT_END;
}

static inline bool is_user_range(const void* addr, size_t size) {
    if (!is_user_address(addr))
        return false;
    uintptr_t end = (uintptr_t)addr + size;
    return (uintptr_t)addr <= end && end <= USER_VIRT_END;
}

static inline bool is_kernel_address(const void* addr) {
    return addr && KERNEL_VIRT_START <= (uintptr_t)addr &&
           (uintptr_t)addr < KERNEL_VIRT_END;
}

static inline bool is_kernel_range(const void* addr, size_t size) {
    if (!is_kernel_address(addr))
        return false;
    uintptr_t end = (uintptr_t)addr + size;
    return (uintptr_t)addr <= end && end <= KERNEL_VIRT_END;
}

void memory_init(void);

struct memory_stats {
    size_t total_kibibytes;
    size_t free_kibibytes;
};

void memory_get_stats(struct memory_stats* out_stats);

void* kmalloc(size_t);
void* kaligned_alloc(size_t alignment, size_t);
void* krealloc(void*, size_t new_size);
void kfree(void*);

DEFINE_FREE(kfree, void*, kfree)

char* kstrdup(const char*);
char* kstrndup(const char*, size_t n);

// Translates virtual address to physical address.
// Panics if the address is not mapped.
phys_addr_t virt_to_phys(void*);

extern struct pagemap* kernel_pagemap;

// Maps the pages to the virtual address.
NODISCARD int pagemap_map(struct pagemap*, uintptr_t virt_addr, size_t pfn,
                          size_t npages, unsigned flags);

// Maps the page to the virtual address. Only the TLB of the current CPU is
// flushed.
NODISCARD int pagemap_map_local(struct pagemap*, uintptr_t virt_addr,
                                size_t pfn, unsigned flags);

// Unmaps the pages at the virtual address.
void pagemap_unmap(struct pagemap*, uintptr_t virt_addr, size_t npages);

// Unmaps the page at the virtual address. Only the TLB of the current CPU is
// flushed.
void pagemap_unmap_local(struct pagemap*, uintptr_t virt_addr);

void pagemap_switch(struct pagemap*);

#define KMAP_MAX_NUM_PER_CPU 4

struct kmap_ctrl {
    size_t num_mapped;
    bool prev_int_flag;
    phys_addr_t phys_addrs[KMAP_MAX_NUM_PER_CPU];
};

// Maps a physical page to the kernel virtual address space.
// KMAP_MAX_NUM_PER_CPU pages can be mapped at the same time for each CPU.
NODISCARD void* kmap(phys_addr_t phys_addr);

NODISCARD void* kmap_page(struct page*);

// Unmaps the kmapped virtual address.
// kunmap must be called in the reverse order of kmap.
void kunmap(void* virt_addr);

struct slab {
    const char* name;
    size_t obj_size;               // Size of each object in bytes
    atomic_size_t total_objs;      // Total number of allocated objects
    atomic_size_t num_active_objs; // Number of objects currently in use
    struct slab_obj* free_list;
    struct mutex lock;
    struct slab* next;
};

void slab_init(struct slab*, const char* name, size_t obj_size);
void* slab_alloc(struct slab*);
void slab_free(struct slab*, void*);

int proc_print_slabinfo(struct file*, struct vec*);

#endif
