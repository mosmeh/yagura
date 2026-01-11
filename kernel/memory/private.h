#pragma once

#include <common/integer.h>
#include <kernel/api/sys/types.h>
#include <kernel/cpu.h>
#include <kernel/memory/memory.h>

#define KMAP_SIZE (KMAP_MAX_NUM_PER_CPU * MAX_NUM_CPUS * PAGE_SIZE)
STATIC_ASSERT(KMAP_SIZE % PAGE_SIZE == 0);

struct vm;
struct vm_region;
struct vm_obj;

void phys_init(void);
void vm_init(void);
void vm_region_init(void);
void vm_obj_init(void);

struct pagemap* pagemap_create(void);
void pagemap_destroy(struct pagemap*);

// Finds a gap in the address space that can fit a region of the given size.
// Returns the start address (in pages) of the gap.
NODISCARD ssize_t vm_find_gap(struct vm*, size_t npages);

// Inserts the region into the vm's region list.
void vm_insert_region(struct vm*, struct vm_region*);

// Removes a region from the vm's region list.
void vm_remove_region(struct vm_region*);

struct vm_region* vm_region_create(struct vm*, size_t start, size_t end);
void vm_region_destroy(struct vm_region*);
struct vm_region* vm_region_clone(struct vm* new_vm, const struct vm_region*);

void vm_region_unset_obj(struct vm_region*);

NODISCARD struct page* vm_region_get_page(struct vm_region*, size_t index,
                                          bool write);
