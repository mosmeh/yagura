#pragma once

#include <common/integer.h>
#include <kernel/cpu.h>
#include <kernel/memory/memory.h>

#define KERNEL_VM_START 0xffff880000000000
#define KERNEL_VM_END 0xffffff0000000000

#define PAGES_START 0xffffff8000000000
#define PAGES_END 0xffffffffc0000000

#define KMAP_START 0xffffffffc0400000
#define KMAP_END 0xffffffffc0800000

struct vm;
struct vm_region;
struct vm_obj;
typedef struct multiboot_info multiboot_info_t;

#define MAX_NUM_PAGES (1 << 20)

void page_init(const multiboot_info_t*);

struct page_table* page_table_create(void);
void page_table_destroy(struct page_table*);

void vm_init(void);
void vm_region_init(void);
void vm_obj_init(void);

NODISCARD bool vm_handle_page_fault(void* virt_addr, unsigned long error_code);

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

NODISCARD bool safe_string_handle_page_fault(struct registers*);
