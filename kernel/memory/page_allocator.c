#include "memory.h"
#include <common/extra.h>
#include <kernel/api/types.h>
#include <kernel/boot_defs.h>
#include <kernel/kprintf.h>
#include <kernel/lock.h>
#include <kernel/multiboot.h>
#include <kernel/panic.h>

#define MAX_NUM_PAGES (1024 * 1024)
#define BITMAP_MAX_LEN (MAX_NUM_PAGES / 32)

static size_t bitmap_len;
static uint32_t bitmap[BITMAP_MAX_LEN];
static mutex lock;

static void bitmap_set(size_t i) {
    ASSERT((i >> 5) < bitmap_len);
    bitmap[i >> 5] |= 1 << (i & 31);
}

static void bitmap_clear(size_t i) {
    ASSERT((i >> 5) < bitmap_len);
    bitmap[i >> 5] &= ~(1 << (i & 31));
}

static ssize_t bitmap_find_first_set(void) {
    for (size_t i = 0; i < bitmap_len; ++i) {
        int b = __builtin_ffs(bitmap[i]);
        if (b > 0) // b == 0 if physical_page_bitmap[i] == 0
            return (i << 5) | (b - 1);
    }
    return -ENOMEM;
}

extern unsigned char kernel_end[];

static void get_available_physical_addr_bounds(const multiboot_info_t* mb_info,
                                               uintptr_t* lower_bound,
                                               uintptr_t* upper_bound) {
    *lower_bound = (uintptr_t)kernel_end - KERNEL_VADDR;

    if (mb_info->flags & MULTIBOOT_INFO_MODS) {
        const multiboot_module_t* mod =
            (const multiboot_module_t*)(mb_info->mods_addr + KERNEL_VADDR);
        for (uint32_t i = 0; i < mb_info->mods_count; ++i) {
            if (*lower_bound < mod->mod_end + 1)
                *lower_bound = mod->mod_end + 1;
            ++mod;
        }
    }

    if (!(mb_info->flags & MULTIBOOT_INFO_MEM_MAP)) {
        *upper_bound = mb_info->mem_upper * 0x400 + 0x100000;
        return;
    }

    uint32_t num_entries =
        mb_info->mmap_length / sizeof(multiboot_memory_map_t);
    const multiboot_memory_map_t* entry =
        (const multiboot_memory_map_t*)(mb_info->mmap_addr + KERNEL_VADDR);

    *upper_bound = *lower_bound;
    for (uint32_t i = 0; i < num_entries; ++i, ++entry) {
        if (entry->type != MULTIBOOT_MEMORY_AVAILABLE)
            continue;

        uintptr_t entry_end = entry->addr + entry->len;
        if (*upper_bound < entry_end)
            *upper_bound = entry_end;
    }
}

static void set_bits_for_available_pages(const multiboot_info_t* mb_info,
                                         uintptr_t lower_bound,
                                         uintptr_t upper_bound) {
    if (!(mb_info->flags & MULTIBOOT_INFO_MEM_MAP)) {
        for (size_t i = div_ceil(lower_bound, PAGE_SIZE);
             i < upper_bound / PAGE_SIZE; ++i)
            bitmap_set(i);
        return;
    }

    uint32_t num_entries =
        mb_info->mmap_length / sizeof(multiboot_memory_map_t);
    const multiboot_memory_map_t* entry =
        (const multiboot_memory_map_t*)(mb_info->mmap_addr + KERNEL_VADDR);

    for (uint32_t i = 0; i < num_entries; ++i, ++entry) {
        if (entry->type != MULTIBOOT_MEMORY_AVAILABLE)
            continue;

        uintptr_t entry_start = entry->addr;
        uintptr_t entry_end = entry->addr + entry->len;

        kprintf("Available region: P0x%08x - P0x%08x (%u MiB)\n", entry_start,
                entry_end, (entry_end - entry_start) / 0x100000);

        if (entry_start < lower_bound)
            entry_start = lower_bound;

        if (entry_start >= entry_end)
            continue;

        for (size_t i = div_ceil(entry_start, PAGE_SIZE);
             i < entry_end / PAGE_SIZE; ++i)
            bitmap_set(i);
    }

    size_t num_pages = 0;
    for (size_t i = 0; i < bitmap_len; ++i) {
        for (size_t b = 0; b < 32; ++b)
            num_pages += (bitmap[i] >> b) & 1;
    }
    kprintf("#Physical pages: %u (%u MiB)\n", num_pages,
            num_pages * PAGE_SIZE / 0x100000);
}

void page_allocator_init(const multiboot_info_t* mb_info) {
    mutex_init(&lock);

    uintptr_t lower_bound;
    uintptr_t upper_bound;
    get_available_physical_addr_bounds(mb_info, &lower_bound, &upper_bound);
    kprintf("Available physical memory address space: P0x%x - P0x%x\n",
            lower_bound, upper_bound);

    // In the current setup, kernel image (including 1MiB offset) has to fit in
    // single page table (< 4MiB), and last page is reserved for quickmap
    ASSERT(lower_bound <= 1023 * PAGE_SIZE);

    bitmap_len = div_ceil(upper_bound, PAGE_SIZE * 32);
    ASSERT(bitmap_len <= BITMAP_MAX_LEN);

    set_bits_for_available_pages(mb_info, lower_bound, upper_bound);
}

uintptr_t page_allocator_alloc(void) {
    mutex_lock(&lock);

    ssize_t first_set = bitmap_find_first_set();
    if (IS_ERR(first_set)) {
        mutex_unlock(&lock);
        return first_set;
    }

    bitmap_clear(first_set);

    mutex_unlock(&lock);
    return first_set * PAGE_SIZE;
}
