#pragma once

#define USER_VIRT_START 0UL
#define USER_VIRT_END 0x800000000000

#define KERNEL_VIRT_START 0xffff800000000000

#define KERNEL_VM_START KERNEL_VIRT_START
#define KERNEL_VM_END 0xffffff0000000000

#define MAX_NUM_PAGES 0x100000 // 4 GiB if PAGE_SIZE == 4 KiB
#define PAGE_ARRAY_START KERNEL_VM_END
#define PAGE_ARRAY_END 0xffffffffc0000000

#define KERNEL_IMAGE_START PAGE_ARRAY_END
// In the current setup, kernel image (including 1MiB offset) has to fit in
// two page tables (< 4MiB).
#define KERNEL_IMAGE_END (KERNEL_IMAGE_START + (1024 << PAGE_SHIFT))

#define KMAP_START KERNEL_IMAGE_END
#define KMAP_END (KMAP_START + KMAP_SIZE)

#define KERNEL_VIRT_END 0xfffffffffffff000 // Reserve last page as a guard

#ifndef __ASSEMBLER__

#include <common/stdint.h>
#include <kernel/arch/x86/include/arch/memory.h>

typedef uint64_t phys_addr_t;

#endif
