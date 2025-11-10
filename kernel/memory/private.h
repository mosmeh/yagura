#pragma once

#include "memory.h"
#include <kernel/cpu.h>

// In the current setup, kernel image (including 1MiB offset) has to fit in
// a single page table (< 4MiB).
#define KERNEL_IMAGE_END (KERNEL_VIRT_ADDR + (1024 << PAGE_SHIFT))

#define PAGES_START KERNEL_IMAGE_END
#define PAGES_END                                                              \
    (PAGES_START + ROUND_UP(MAX_NUM_PAGES * sizeof(struct page), PAGE_SIZE))

#define KMAP_START PAGES_END
#define KMAP_END (KMAP_START + MAX_NUM_KMAPS_PER_CPU * MAX_NUM_CPUS * PAGE_SIZE)

#define KERNEL_VM_START KMAP_END

// Last 4MiB is for recursive mapping
#define KERNEL_VM_END 0xffc00000

struct vm;
typedef struct multiboot_info multiboot_info_t;

#define MAX_NUM_PAGES (1 << 20)

void page_init(const multiboot_info_t*);

struct page_directory* page_directory_create(void);
void page_directory_destroy(struct page_directory*);

void vm_init(void);

// Finds a gap in the address space that can fit a region of the given size.
// Returns the region before the gap, or NULL if the vm is empty.
// If start is not NULL, (the start virtual address >> PAGE_SHIFT) of the gap is
// stored in *start.
struct vm_region* vm_find_gap(const struct vm*, size_t npages, size_t* start);

// Inserts the region `inserted` after the region `prev`.
// If `prev` is NULL, `inserted` is inserted at the beginning of the vm's region
// list.
void vm_insert_region_after(struct vm*, struct vm_region* prev,
                            struct vm_region* inserted);

// Removes a region from the vm's region list.
void vm_region_remove(struct vm_region*);

void vm_obj_init(void);
