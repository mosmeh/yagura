#pragma once

#include "forward.h"
#include <stdint.h>

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
void memory_switch_page_directory(page_directory* pd);

int memory_map_to_anonymous_region(uintptr_t virtual_addr, uintptr_t size,
                                   uint16_t flags);
int memory_map_to_physical_range(uintptr_t virtual_addr,
                                 uintptr_t physical_addr, uintptr_t size,
                                 uint16_t flags);
uint16_t memory_prot_to_map_flags(int prot);

uintptr_t memory_alloc_kernel_virtual_addr_range(uintptr_t size);
