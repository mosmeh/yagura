#pragma once

#include "memory.h"
#include <kernel/api/sys/types.h>
#include <kernel/cpu.h>

// In the current setup, kernel image (including 1MiB offset) has to fit in
// single page table (< 4MiB).
#define KERNEL_IMAGE_END (KERNEL_VIRT_ADDR + 1024 * PAGE_SIZE)

#define KMAP_START KERNEL_IMAGE_END
#define KMAP_END                                                               \
    (KMAP_START + MAX_NUM_KMAPS_PER_TASK * MAX_NUM_CPUS * PAGE_SIZE)

#define PAGES_START KMAP_END

// Last 4MiB is for recursive mapping
#define KERNEL_VM_END 0xffc00000

typedef struct multiboot_info multiboot_info_t;

// Returns the start virtual address of the kernel vm space.
uintptr_t page_init(const multiboot_info_t*);

struct page* page_get(size_t pfn);
size_t page_to_pfn(struct page*);

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

struct page_directory* page_directory_create(void);
void page_directory_destroy(struct page_directory*);

void vm_init(uintptr_t kernel_vm_start);

// Finds a gap in the address space that can fit a region of the given size.
// Returns the region before the gap, or NULL if the vm is empty.
// If start is not NULL, the start virtual address / PAGE_SIZE of the gap is
// stored in *start.
struct vm_region* vm_find_gap(struct vm*, size_t npages, size_t* start);

// Inserts the region `inserted` after the region `prev`.
void vm_insert_region_after(struct vm*, struct vm_region* prev,
                            struct vm_region* inserted);

// Removes a region from the vm's region list.
void vm_region_remove(struct vm_region*);

void vm_obj_init(void);
