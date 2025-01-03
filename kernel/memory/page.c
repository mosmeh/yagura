#include "memory.h"
#include <common/extra.h>
#include <kernel/api/sys/types.h>
#include <kernel/kmsg.h>
#include <kernel/lock.h>
#include <kernel/multiboot.h>
#include <kernel/panic.h>
#include <kernel/system.h>
#include <stdbool.h>

#define MAX_NUM_PAGES (1024 * 1024)
#define BITMAP_INDEX(i) ((i) / 32)
#define BITMAP_MAX_LEN BITMAP_INDEX(MAX_NUM_PAGES)

static size_t bitmap_len;
static uint32_t bitmap[BITMAP_MAX_LEN];
static uint8_t ref_counts[MAX_NUM_PAGES];
static struct mutex lock;

static bool bitmap_get(size_t i) {
    ASSERT(BITMAP_INDEX(i) < bitmap_len);
    return bitmap[BITMAP_INDEX(i)] & (1U << (i & 31));
}

static void bitmap_set(size_t i) {
    ASSERT(BITMAP_INDEX(i) < bitmap_len);
    bitmap[BITMAP_INDEX(i)] |= 1U << (i & 31);
}

static void bitmap_clear(size_t i) {
    ASSERT(BITMAP_INDEX(i) < bitmap_len);
    bitmap[BITMAP_INDEX(i)] &= ~(1U << (i & 31));
}

static ssize_t bitmap_find_first_set(void) {
    for (size_t i = 0; i < bitmap_len; ++i) {
        int b = __builtin_ffs(bitmap[i]);
        if (b > 0) // b == 0 if bitmap[i] == 0
            return (i << 5) | (b - 1);
    }
    return -ENOMEM;
}

static void get_available_physical_addr_bounds(const multiboot_info_t* mb_info,
                                               uintptr_t* lower_bound,
                                               uintptr_t* upper_bound) {
    *lower_bound = (uintptr_t)kernel_end - KERNEL_VIRT_ADDR;

    if (!(mb_info->flags & MULTIBOOT_INFO_MEM_MAP)) {
        *upper_bound = mb_info->mem_upper * 0x400 + 0x100000;
        return;
    }

    uint32_t num_entries =
        mb_info->mmap_length / sizeof(multiboot_memory_map_t);
    const multiboot_memory_map_t* entry =
        (const multiboot_memory_map_t*)(mb_info->mmap_addr + KERNEL_VIRT_ADDR);

    *upper_bound = *lower_bound;
    for (uint32_t i = 0; i < num_entries; ++i, ++entry) {
        if (entry->type != MULTIBOOT_MEMORY_AVAILABLE)
            continue;

        uintptr_t entry_end = entry->addr + entry->len;
        if (*upper_bound < entry_end)
            *upper_bound = entry_end;
    }
}

static struct memory_stats stats;

static void bitmap_init(const multiboot_info_t* mb_info, uintptr_t lower_bound,
                        uintptr_t upper_bound) {
    bitmap_len = DIV_CEIL(upper_bound, PAGE_SIZE * 32);
    ASSERT(bitmap_len <= BITMAP_MAX_LEN);

    if (mb_info->flags & MULTIBOOT_INFO_MEM_MAP) {
        uint32_t num_entries =
            mb_info->mmap_length / sizeof(multiboot_memory_map_t);
        const multiboot_memory_map_t* entry =
            (const multiboot_memory_map_t*)(mb_info->mmap_addr +
                                            KERNEL_VIRT_ADDR);

        for (uint32_t i = 0; i < num_entries; ++i, ++entry) {
            if (entry->type != MULTIBOOT_MEMORY_AVAILABLE)
                continue;

            uintptr_t entry_start = entry->addr;
            uintptr_t entry_end = entry->addr + entry->len;

            kprintf("page: available region P0x%08x - P0x%08x (%u MiB)\n",
                    entry_start, entry_end,
                    (entry_end - entry_start) / 0x100000);

            if (entry_start < lower_bound)
                entry_start = lower_bound;

            if (entry_start >= entry_end)
                continue;

            for (size_t i = DIV_CEIL(entry_start, PAGE_SIZE);
                 i < entry_end / PAGE_SIZE; ++i)
                bitmap_set(i);
        }
    } else {
        for (size_t i = DIV_CEIL(lower_bound, PAGE_SIZE);
             i < upper_bound / PAGE_SIZE; ++i)
            bitmap_set(i);
    }

    if (mb_info->flags & MULTIBOOT_INFO_MODS) {
        const multiboot_module_t* mod =
            (const multiboot_module_t*)(mb_info->mods_addr + KERNEL_VIRT_ADDR);
        for (uint32_t i = 0; i < mb_info->mods_count; ++i) {
            kprintf("page: module P0x%08x - P0x%08x (%u MiB)\n", mod->mod_start,
                    mod->mod_end, (mod->mod_end - mod->mod_start) / 0x100000);
            for (size_t i = mod->mod_start / PAGE_SIZE;
                 i < DIV_CEIL(mod->mod_end, PAGE_SIZE); ++i)
                bitmap_clear(i);
            ++mod;
        }
    }

    size_t num_pages = 0;
    for (size_t i = 0; i < bitmap_len * 32; ++i) {
        if (bitmap_get(i)) {
            ++num_pages;
        } else {
            // By setting initial reference counts to be non-zero values,
            // the reference counts of these pages will never reach zero,
            // avoiding accidentally marking the pages available for allocation.
            ref_counts[i] = UINT8_MAX;
        }
    }
    stats.total_kibibytes = stats.free_kibibytes = num_pages * PAGE_SIZE / 1024;
    kprintf("page: #physical pages = %u (%u KiB)\n", num_pages,
            stats.total_kibibytes);
}

void page_init(const multiboot_info_t* mb_info) {
    // In the current setup, kernel image (including 1MiB offset) has to fit in
    // single page table (< 4MiB), and last two pages are reserved for quickmap
    ASSERT((uintptr_t)kernel_end <= KERNEL_VIRT_ADDR + 1022 * PAGE_SIZE);

    uintptr_t lower_bound;
    uintptr_t upper_bound;
    get_available_physical_addr_bounds(mb_info, &lower_bound, &upper_bound);
    kprintf("page: available physical memory address space P%#x - P%#x\n",
            lower_bound, upper_bound);

    bitmap_init(mb_info, lower_bound, upper_bound);
}

uintptr_t page_alloc(void) {
    mutex_lock(&lock);

    ssize_t first_set = bitmap_find_first_set();
    if (IS_ERR(first_set)) {
        mutex_unlock(&lock);
        kprint("page: out of physical pages\n");
        return first_set;
    }

    ASSERT(ref_counts[first_set] == 0);
    ASSERT(bitmap_get(first_set));

    ref_counts[first_set] = 1;
    bitmap_clear(first_set);
    stats.free_kibibytes -= PAGE_SIZE / 1024;

    mutex_unlock(&lock);
    return first_set * PAGE_SIZE;
}

void page_ref(uintptr_t phys_addr) {
    ASSERT(phys_addr % PAGE_SIZE == 0);
    size_t index = phys_addr / PAGE_SIZE;
    if (BITMAP_INDEX(index) >= bitmap_len)
        return;

    mutex_lock(&lock);

    ASSERT(ref_counts[index] > 0);
    ASSERT(!bitmap_get(index));

    if (ref_counts[index] < UINT8_MAX)
        ++ref_counts[index];

    mutex_unlock(&lock);
}

void page_unref(uintptr_t phys_addr) {
    ASSERT(phys_addr % PAGE_SIZE == 0);
    size_t index = phys_addr / PAGE_SIZE;
    if (BITMAP_INDEX(index) >= bitmap_len)
        return;

    mutex_lock(&lock);

    ASSERT(ref_counts[index] > 0);
    ASSERT(!bitmap_get(index));

    // When the reference count is UINT8_MAX, we can't tell whether it actually
    // has exactly UINT8_MAX references or the count was saturated.
    // To be safe, we never decrement the reference count if count == UINT8_MAX
    // assuming the count was saturated.
    if (ref_counts[index] < UINT8_MAX) {
        if (--ref_counts[index] == 0) {
            bitmap_set(index);
            stats.free_kibibytes += PAGE_SIZE / 1024;
        }
    }

    mutex_unlock(&lock);
}

void memory_get_stats(struct memory_stats* out_stats) {
    mutex_lock(&lock);
    *out_stats = stats;
    mutex_unlock(&lock);
}
