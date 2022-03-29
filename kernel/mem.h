#pragma once

#include "forward.h"
#include <stdint.h>

#define MEM_WRITE 0x2
#define MEM_USER 0x4
#define MEM_GLOBAL 0x100

void mem_init(const multiboot_info_t*);

void mem_switch_page_directory(uintptr_t physical_addr);
uintptr_t mem_clone_current_page_directory_and_get_physical_addr(void);

int mem_map_to_private_anonymous_region(uintptr_t virtual_addr, uintptr_t size,
                                        uint16_t flags);
int mem_map_to_shared_physical_range(uintptr_t virtual_addr,
                                     uintptr_t physical_addr, uintptr_t size,
                                     uint16_t flags);
uint16_t mem_prot_to_flags(int prot);
