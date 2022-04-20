#pragma once

#include "forward.h"
#include <stdint.h>

#define MEM_WRITE 0x2
#define MEM_USER 0x4
#define MEM_GLOBAL 0x100

// we use an unused bit in page table entries to indicate the page should be
// linked, not copied, when cloning a page directory
#define MEM_SHARED 0x200

void mem_init(const multiboot_info_t*);

uintptr_t mem_virtual_to_physical_addr(uintptr_t virtual_addr);

page_directory* mem_current_page_directory(void);
page_directory* mem_create_page_directory(void);
page_directory* mem_clone_current_page_directory(void);
void mem_switch_page_directory(page_directory* pd);

int mem_map_to_anonymous_region(uintptr_t virtual_addr, uintptr_t size,
                                uint16_t flags);
int mem_map_to_physical_range(uintptr_t virtual_addr, uintptr_t physical_addr,
                              uintptr_t size, uint16_t flags);
uint16_t mem_prot_to_map_flags(int prot);

uintptr_t mem_alloc_kernel_virtual_addr_range(uintptr_t size);
