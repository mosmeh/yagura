#pragma once

#include "forward.h"
#include <stddef.h>
#include <stdint.h>

#define MEM_WRITE 0x2
#define MEM_USER 0x4

void mem_init(const multiboot_info_t*);

volatile page_directory* mem_current_page_directory(void);
void mem_switch_page_directory(uintptr_t physical_addr);
page_directory* mem_clone_page_directory(void);

volatile page_table* mem_get_page_table(size_t pd_idx);

uintptr_t mem_get_physical_addr(uintptr_t virtual_addr);

volatile page_table_entry*
mem_map_virtual_addr_to_any_page(uintptr_t virtual_addr, uint32_t flags);
void mem_map_virtual_addr_range_to_any_pages(uintptr_t start, uintptr_t end,
                                             uint32_t flags);
