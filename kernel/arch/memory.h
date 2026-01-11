#pragma once

#include <arch/memory.h>

#ifndef __ASSEMBLER__

#include <common/macros.h>
#include <stdbool.h>
#include <stddef.h>

struct pagemap;
struct registers;

NODISCARD int arch_map_page(struct pagemap*, uintptr_t virt_addr, size_t pfn,
                            unsigned flags);
void arch_unmap_page(struct pagemap*, uintptr_t virt_addr);

void arch_flush_tlb_all(void);
void arch_flush_tlb_single(uintptr_t virt_addr);

void arch_full_memory_barrier(void);

#endif
