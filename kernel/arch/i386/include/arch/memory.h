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

#define MAX_NUM_PAGES 0x100000 // 4 GiB if PAGE_SIZE == 4 KiB
#define PAGE_ARRAY_START KMAP_END
#define PAGE_ARRAY_END                                                         \
    (PAGE_ARRAY_START +                                                        \
     ROUND_UP(MAX_NUM_PAGES * sizeof(struct page), PAGE_SIZE))

#define KERNEL_VM_START PAGE_ARRAY_END
#define KERNEL_VM_END 0xfffff000 // Reserve last page as a guard

#define KERNEL_VIRT_END KERNEL_VM_END

#ifndef __ASSEMBLER__

#include <kernel/arch/x86/include/arch/memory.h>
#include <stdint.h>

typedef uint32_t phys_addr_t;

#endif
