#pragma once

#include "memory.h"
#include <common/extra.h>
#include <kernel/cpu.h>
#include <kernel/lock.h>
#include <stdalign.h>
#include <stdint.h>

// In the current setup, kernel image (including 1MiB offset) has to fit in
// single page table (< 4MiB).
#define KERNEL_IMAGE_END (KERNEL_VIRT_ADDR + 1024 * PAGE_SIZE)

#define KMAP_START KERNEL_IMAGE_END
#define KMAP_END                                                               \
    (KMAP_START + MAX_NUM_KMAPS_PER_TASK * MAX_NUM_CPUS * PAGE_SIZE)

#define PAGES_START KMAP_END

// Last 4MiB is for recursive mapping
#define KERNEL_HEAP_END 0xffc00000

typedef struct multiboot_info multiboot_info_t;

struct page_directory {
    alignas(PAGE_SIZE) uint32_t entries[1024];
};

#define PAGE_RESERVED 0x1
#define PAGE_ALLOCATED 0x2
#define PAGE_DIRTY 0x4

struct page {
    size_t offset;
    unsigned flags;    // PAGE_*
    struct page* next; // offset < next->offset
};

// Returns the start virtual page index of the kernel heap space.
size_t page_init(const multiboot_info_t*);

size_t page_to_phys_index(struct page*);

// Commits pages without allocating them.
bool page_commit(size_t n);

void page_uncommit(size_t n);

// Commits and allocates a page.
struct page* page_alloc(void);

// Returns the index of the allocated page or 0 if failed.
size_t page_alloc_raw(void);

// Allocates a page without committing it. At least one page should have been
// committed before calling this function.
struct page* page_alloc_committed(void);

// Frees and uncommits a page.
void page_free(struct page*);
void page_free_raw(size_t index);

struct page_directory* page_directory_create(void);
void page_directory_destroy(struct page_directory*);

struct vm;

void vm_init(size_t kernel_heap_start);

// Finds a gap in the address space that can fit a region of the given size.
// Returns the region before the gap, or NULL if the vm is empty.
// If start is not NULL, the start page index of the gap is stored.
struct vm_region* vm_find_gap(struct vm*, size_t npages, size_t* start);

// Inserts the region `inserted` after the region `prev`.
void vm_insert_region_after(struct vm*, struct vm_region* prev,
                            struct vm_region* inserted);

// Removes a region from the vm's region list.
void vm_region_remove(struct vm_region*);

void vobj_init(void);
struct vobj* vobj_clone(struct vobj* vobj);
void vobj_remove_region(struct vobj*, struct vm_region*);
