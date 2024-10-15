#include "memory.h"
#include "private.h"
#include <common/extra.h>
#include <common/string.h>
#include <kernel/api/sys/types.h>
#include <kernel/kmsg.h>
#include <kernel/lock.h>
#include <kernel/multiboot.h>
#include <kernel/panic.h>
#include <kernel/system.h>
#include <stdbool.h>

#define PAGES_MAX_LEN (1024 * 1024)
#define BITMAP_INDEX(i) ((i) / 32)
#define BITMAP_MASK(i) (1 << ((i) & 31))
#define BITMAP_MAX_LEN BITMAP_INDEX(PAGES_MAX_LEN)

static size_t pages_len;
static size_t bitmap_len;
static atomic_uint bitmap[BITMAP_MAX_LEN];

static bool bitmap_get(size_t i) {
    ASSERT(i < pages_len);
    return bitmap[BITMAP_INDEX(i)] & BITMAP_MASK(i);
}

// Returns the previous state of the bit.
static bool bitmap_set(size_t i) {
    ASSERT(i < pages_len);
    uint32_t prev = atomic_fetch_or(&bitmap[BITMAP_INDEX(i)], BITMAP_MASK(i));
    return prev & BITMAP_MASK(i);
}

// Returns the previous state of the bit.
static bool bitmap_clear(size_t i) {
    ASSERT(i < pages_len);
    uint32_t prev = atomic_fetch_and(&bitmap[BITMAP_INDEX(i)], ~BITMAP_MASK(i));
    return prev & BITMAP_MASK(i);
}

static size_t bitmap_get_free(void) {
    for (size_t i = 0; i < bitmap_len; ++i) {
        for (;;) {
            uint32_t v = bitmap[i];
            int b = __builtin_ffs(v);
            if (b == 0) // v == 0
                goto next;
            uint32_t new_v = v & ~BITMAP_MASK(b - 1);
            if (!atomic_compare_exchange_weak(&bitmap[i], &v, new_v))
                continue;
            return i * 32 + (b - 1);
        }
    next:;
    }
    return 0;
}

static void bitmap_init(const multiboot_info_t* mb_info, uintptr_t start_addr,
                        uintptr_t end_addr) {
    bitmap_len = DIV_CEIL(end_addr, PAGE_SIZE * 32);
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

            if (entry_start < start_addr)
                entry_start = start_addr;

            if (entry_start >= entry_end)
                continue;

            for (size_t i = DIV_CEIL(entry_start, PAGE_SIZE);
                 i < entry_end / PAGE_SIZE; ++i)
                bitmap_set(i);
        }
    } else {
        for (size_t i = DIV_CEIL(start_addr, PAGE_SIZE);
             i < end_addr / PAGE_SIZE; ++i)
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

    bitmap_clear(0); // To use page index 0 as the invalid index
}

static size_t total_pages;
static atomic_size_t free_pages;

size_t page_init(const multiboot_info_t* mb_info) {
    ASSERT((uintptr_t)kernel_end <= KERNEL_IMAGE_END);

    uintptr_t start_addr = (uintptr_t)kernel_end - KERNEL_VIRT_ADDR;
    uintptr_t end_addr = start_addr;
    if (mb_info->flags & MULTIBOOT_INFO_MEM_MAP) {
        uint32_t num_entries =
            mb_info->mmap_length / sizeof(multiboot_memory_map_t);
        const multiboot_memory_map_t* entry =
            (const multiboot_memory_map_t*)(mb_info->mmap_addr +
                                            KERNEL_VIRT_ADDR);
        for (uint32_t i = 0; i < num_entries; ++i, ++entry) {
            if (entry->type != MULTIBOOT_MEMORY_AVAILABLE)
                continue;
            uintptr_t entry_end = entry->addr + entry->len;
            if (end_addr < entry_end)
                end_addr = entry_end;
        }
    } else {
        end_addr = mb_info->mem_upper * 0x400 + 0x100000;
    }

    kprintf("page: available physical memory address space P%#x - P%#x\n",
            start_addr, end_addr);

    pages_len = DIV_CEIL(end_addr, PAGE_SIZE);
    bitmap_init(mb_info, start_addr, end_addr);

    size_t pages_size = ROUND_UP(pages_len * sizeof(struct page), PAGE_SIZE);
    for (size_t i = 0; i < pages_size / PAGE_SIZE; ++i) {
        size_t phys_index = page_alloc_raw();
        ASSERT(phys_index);
        ASSERT_OK(page_table_map_local(PAGES_START / PAGE_SIZE + i, phys_index,
                                       PTE_WRITE | PTE_GLOBAL));
    }

    struct page* pages = (struct page*)PAGES_START;
    for (size_t i = 0; i < pages_len; ++i) {
        if (bitmap_get(i))
            ++total_pages;
        else
            pages[i].flags = PAGE_RESERVED;
    }

    free_pages = total_pages;
    kprintf("page: #total pages = %u\n", total_pages);

    return (PAGES_START + pages_size) / PAGE_SIZE;
}

size_t page_to_phys_index(struct page* page) {
    ASSERT(page);
    struct page* pages = (struct page*)PAGES_START;
    ASSERT(pages <= page && page < pages + pages_len);
    return page - pages;
}

static atomic_size_t committed_pages;

bool page_commit(size_t n) {
    if (n == 0)
        return true;
    for (;;) {
        size_t old = committed_pages;
        size_t new = old + n;
        if (new > total_pages || new <= old)
            return false; // Never overcommit
        if (atomic_compare_exchange_weak(&committed_pages, &old, new))
            return true;
    }
}

static struct page* init_new_page(size_t index) {
    struct page* page = (struct page*)PAGES_START + index;
    ASSERT(!page->flags);
    ASSERT(!page->next);
    *page = (struct page){
        .flags = PAGE_ALLOCATED,
    };
    return page;
}

struct page* page_alloc(void) {
    size_t index = page_alloc_raw();
    if (!index)
        return ERR_PTR(-ENOMEM);
    return init_new_page(index);
}

static size_t alloc_committed_raw(void) {
    // ASSERT(committed_pages > total_pages - free_pages);
    --free_pages;
    ssize_t i = bitmap_get_free();
    ASSERT(i);
    return i;
}

size_t page_alloc_raw(void) {
    /*if (!page_commit(1))
        return 0;*/
    return alloc_committed_raw();
}

struct page* page_alloc_committed(void) {
    size_t index = alloc_committed_raw();
    return init_new_page(index);
}

void page_free(struct page* page) {
    ASSERT(page);
    ASSERT(page->flags == PAGE_ALLOCATED);
    *page = (struct page){0};
    page_free_raw(page_to_phys_index(page));
}

void page_free_raw(size_t index) {
    ASSERT(!bitmap_set(index));
    ++free_pages;
    // ASSERT(atomic_fetch_sub(&committed_pages, 1) > 0);
}

void memory_get_stats(struct memory_stats* out_stats) {
    *out_stats = (struct memory_stats){
        .total_kibibytes = total_pages * PAGE_SIZE / 1024,
        .free_kibibytes = free_pages * PAGE_SIZE / 1024,
        .committed_kibibytes = committed_pages * PAGE_SIZE / 1024,
    };
}
