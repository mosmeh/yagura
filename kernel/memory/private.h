#pragma once

#include <common/integer.h>
#include <kernel/cpu.h>
#include <kernel/memory/memory.h>

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
struct vm_region;
struct vm_obj;
typedef struct multiboot_info multiboot_info_t;

#define MAX_NUM_PAGES (1 << 20)

void page_init(const multiboot_info_t*);

struct page_directory* page_directory_create(void);
void page_directory_destroy(struct page_directory*);

void vm_init(void);
void vm_region_init(void);
void vm_obj_init(void);

NODISCARD bool vm_handle_page_fault(void* virt_addr, uint32_t error_code);

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

NODISCARD struct page* vm_region_handle_page_fault(struct vm_region*,
                                                   size_t index,
                                                   uint32_t error_code);

NODISCARD bool safe_string_handle_page_fault(struct registers*);
