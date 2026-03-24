#pragma once

#include <arch/memory.h>

#ifndef __ASSEMBLER__

#include <common/macros.h>
#include <common/stdbool.h>
#include <common/stddef.h>
#include <kernel/api/sys/types.h>

struct pagemap;

// Returns a positive value if the TLB entry has to be invalidated to reflect
// the new mapping, 0 if no invalidation is needed, or a negative error code on
// failure.
NODISCARD int arch_map_page(struct pagemap*, uintptr_t virt_addr, size_t pfn,
                            unsigned flags);

// Returns true if a page was unmapped, false if a mapping was not present.
bool arch_unmap_page(struct pagemap*, uintptr_t virt_addr);

void arch_switch_pagemap(struct pagemap*);

void arch_invalidate_tlb_page(uintptr_t virt_addr);

void arch_full_memory_barrier(void);

#endif
