#pragma once

#define USER_VIRT_START 0UL
#define USER_VIRT_END 0xc0000000

#define KERNEL_VIRT_START USER_VIRT_END

#define KERNEL_IMAGE_START KERNEL_VIRT_START
// In the current setup, kernel image (including 1MiB offset) has to fit in
// a single page table (< 4MiB).
#define KERNEL_IMAGE_END (KERNEL_IMAGE_START + (1024 << PAGE_SHIFT))

#define KMAP_START KERNEL_IMAGE_END
#define KMAP_END (KMAP_START + KMAP_SIZE)

#define MAX_NUM_PAGES (1UL << (32 - PAGE_SHIFT)) // 4 GiB physical address space
#define PAGE_BITMAP_SIZE DIV_CEIL(MAX_NUM_PAGES, CHAR_BIT)
#define PAGE_ARRAY_SIZE ROUND_UP(MAX_NUM_PAGES * sizeof(struct page), PAGE_SIZE)
#define PAGE_ATLAS_SIZE (PAGE_BITMAP_SIZE + PAGE_ARRAY_SIZE)
#define PAGE_ATLAS_START KMAP_END
#define PAGE_ATLAS_END (PAGE_ATLAS_START + PAGE_ATLAS_SIZE)

#define KERNEL_VM_START PAGE_ATLAS_END
#define KERNEL_VM_END 0xfffff000 // Reserve last page as a guard

#define KERNEL_VIRT_END KERNEL_VM_END

#ifndef __ASSEMBLER__

#include <common/stdint.h>
#include <kernel/arch/x86/include/arch/memory.h>

typedef uint32_t phys_addr_t;

#endif
