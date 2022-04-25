#pragma once

#include <kernel/forward.h>
#include <stddef.h>
#include <stdint.h>

// kernel heap starts right after the quickmap page
#define KERNEL_HEAP_START (KERNEL_VADDR + 1024 * PAGE_SIZE)

// last 4MiB is for recursive mapping
#define KERNEL_HEAP_END 0xffc00000

void kernel_vaddr_allocator_init(void);
uintptr_t kernel_vaddr_allocator_alloc(size_t size);
void kernel_vaddr_allocator_free(uintptr_t addr, size_t size);

typedef struct range_allocator {
    uintptr_t start;
    uintptr_t end;
    struct range* ranges;
} range_allocator;

int range_allocator_init(range_allocator* allocator, uintptr_t start,
                         uintptr_t end);
void range_allocator_destroy(range_allocator* allocator);
uintptr_t range_allocator_alloc(range_allocator* allocator, size_t size);
int range_allocator_free(range_allocator* allocator, uintptr_t addr,
                         size_t size);
int range_allocator_clone(range_allocator* to, range_allocator* from);

#define MEMORY_WRITE 0x2
#define MEMORY_USER 0x4
#define MEMORY_GLOBAL 0x100

// we use an unused bit in page table entries to indicate the page should be
// linked, not copied, when cloning a page directory
#define MEMORY_SHARED 0x200

void memory_init(const multiboot_info_t*);

uintptr_t memory_virtual_to_physical_addr(uintptr_t virtual_addr);

page_directory* memory_current_page_directory(void);
page_directory* memory_create_page_directory(void);
page_directory* memory_clone_current_page_directory(void);
void memory_destroy_current_page_directory(void);
void memory_switch_page_directory(page_directory* pd);

int memory_map_to_anonymous_region(uintptr_t virtual_addr, uintptr_t size,
                                   uint16_t flags);
int memory_map_to_physical_range(uintptr_t virtual_addr,
                                 uintptr_t physical_addr, uintptr_t size,
                                 uint16_t flags);
int memory_copy_mapping(uintptr_t to_virtual_addr, uintptr_t from_virtual_addr,
                        uintptr_t size, uint16_t flags);
void memory_unmap(uintptr_t virtual_addr, uintptr_t size);
uint16_t memory_prot_to_map_flags(int prot);

void page_allocator_init(const multiboot_info_t* mb_info);
uintptr_t page_allocator_alloc(void);
void page_allocator_ref_page(uintptr_t physical_addr);
void page_allocator_unref_page(uintptr_t physical_addr);
