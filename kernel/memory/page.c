#include "memory.h"
#include "private.h"
#include <common/extra.h>
#include <common/string.h>
#include <kernel/api/sys/types.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/lock.h>
#include <kernel/multiboot.h>
#include <kernel/panic.h>
#include <kernel/system.h>
#include <stdbool.h>

#define BITMAP_INDEX(i) ((i) / 32)
#define BITMAP_MASK(i) (1U << ((i) & 31))
#define BITMAP_MAX_LEN BITMAP_INDEX(MAX_NUM_PAGES)

static size_t pfn_end; // Maximum physical frame number + 1
static atomic_uint bitmap[BITMAP_MAX_LEN];

static bool bitmap_get(size_t i) {
    ASSERT(i < pfn_end);
    return bitmap[BITMAP_INDEX(i)] & BITMAP_MASK(i);
}

// Returns the previous state of the bit.
static bool bitmap_set(size_t i) {
    ASSERT(i < pfn_end);
    uint32_t prev = atomic_fetch_or(&bitmap[BITMAP_INDEX(i)], BITMAP_MASK(i));
    return prev & BITMAP_MASK(i);
}

// Returns the previous state of the bit.
static bool bitmap_clear(size_t i) {
    ASSERT(i < pfn_end);
    uint32_t prev = atomic_fetch_and(&bitmap[BITMAP_INDEX(i)], ~BITMAP_MASK(i));
    return prev & BITMAP_MASK(i);
}

static ssize_t bitmap_get_free(void) {
    for (size_t i = 0; i < pfn_end / 32; ++i) {
        for (;;) {
            uint32_t v = bitmap[i];
            int b = __builtin_ffs(v);
            if (b == 0) // v == 0
                break;
            uint32_t new_v = v & ~BITMAP_MASK(b - 1);
            if (atomic_compare_exchange_weak(&bitmap[i], &v, new_v))
                return i * 32 + (b - 1);
        }
    }
    return -ENOMEM;
}

static void detect_memory(const multiboot_info_t* mb_info) {
    // We don't know the size of the physical memory yet.
    // Set the maximum possible value so that we can modify the entire bitmap.
    pfn_end = MAX_NUM_PAGES;

    ASSERT(KERNEL_VIRT_ADDR < (uintptr_t)kernel_end &&
           (uintptr_t)kernel_end <= KERNEL_IMAGE_END);
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

            uintptr_t entry_start = entry->addr;
            uintptr_t entry_end = entry->addr + entry->len;

            kprintf("page: available region P0x%08x - P0x%08x (%u MiB)\n",
                    entry_start, entry_end,
                    (entry_end - entry_start) / 0x100000);

            if (entry_start < start_addr)
                entry_start = start_addr;

            if (entry_start >= entry_end)
                continue;

            if (end_addr < entry_end)
                end_addr = entry_end;

            for (size_t i = DIV_CEIL(entry_start, PAGE_SIZE);
                 i < entry_end >> PAGE_SHIFT; ++i)
                bitmap_set(i);
        }
    } else {
        end_addr = MAX(start_addr, mb_info->mem_upper * 0x400 + 0x100000);

        for (size_t i = DIV_CEIL(start_addr, PAGE_SIZE);
             i < end_addr >> PAGE_SHIFT; ++i)
            bitmap_set(i);
    }

    if (mb_info->flags & MULTIBOOT_INFO_MODS) {
        const multiboot_module_t* mod =
            (const multiboot_module_t*)(mb_info->mods_addr + KERNEL_VIRT_ADDR);
        for (uint32_t i = 0; i < mb_info->mods_count; ++i) {
            kprintf("page: module P0x%08x - P0x%08x (%u MiB)\n", mod->mod_start,
                    mod->mod_end, (mod->mod_end - mod->mod_start) / 0x100000);
            for (size_t i = mod->mod_start >> PAGE_SHIFT;
                 i < DIV_CEIL(mod->mod_end, PAGE_SIZE); ++i)
                bitmap_clear(i);
            ++mod;
        }
    }

    kprintf("page: available physical memory address space P%#x - P%#x\n",
            start_addr, end_addr);

    pfn_end = end_addr >> PAGE_SHIFT;
    ASSERT(pfn_end > 0);
    ASSERT(pfn_end <= MAX_NUM_PAGES);
}

static size_t total_pages;
static atomic_size_t free_pages;

void page_init(const multiboot_info_t* mb_info) {
    detect_memory(mb_info);

    size_t npages_to_map = DIV_CEIL(pfn_end * sizeof(struct page), PAGE_SIZE);
    for (size_t i = 0; i < npages_to_map; ++i) {
        ssize_t pfn = page_alloc_raw();
        ASSERT_OK(pfn);
        ASSERT_OK(page_table_map_local(PAGES_START + (i << PAGE_SHIFT), pfn,
                                       PTE_WRITE | PTE_GLOBAL));
    }

    for (size_t i = 0; i < pfn_end; ++i) {
        if (bitmap_get(i))
            ++total_pages;
        else
            page_get(i)->flags = PAGE_RESERVED;
    }

    free_pages = total_pages;
    kprintf("page: #total pages = %u\n", total_pages);
}

struct page* page_get(size_t pfn) {
    ASSERT(pfn < MAX_NUM_PAGES);
    return (struct page*)PAGES_START + pfn;
}

size_t page_to_pfn(const struct page* page) {
    ASSERT(page);
    struct page* pages = (struct page*)PAGES_START;
    ASSERT(pages <= page && page < pages + MAX_NUM_PAGES);
    return page - pages;
}

struct page* page_alloc(void) {
    ssize_t pfn = page_alloc_raw();
    if (IS_ERR(pfn))
        return ERR_PTR(pfn);
    struct page* page = page_get(pfn);
    ASSERT(!page->flags);
    ASSERT(!page->next);
    *page = (struct page){
        .flags = PAGE_ALLOCATED,
    };
    return page;
}

ssize_t page_alloc_raw(void) {
    --free_pages;
    return bitmap_get_free();
}

void page_free(struct page* page) {
    if (!page)
        return;
    ASSERT(page->flags & PAGE_ALLOCATED);
    *page = (struct page){0};
    page_free_raw(page_to_pfn(page));
}

void page_free_raw(size_t pfn) {
    ASSERT(!bitmap_set(pfn));
    ++free_pages;
}

void page_fill(struct page* page, unsigned char value, size_t offset,
               size_t nbytes) {
    ASSERT(offset + nbytes <= PAGE_SIZE);
    bool int_flag = push_cli();
    unsigned char* mapped_page = kmap_page(page);
    memset(mapped_page + offset, value, nbytes);
    kunmap(mapped_page);
    pop_cli(int_flag);
}

void page_copy(struct page* dest, struct page* src) {
    bool int_flag = push_cli();
    void* src_mapped = kmap_page(src);
    page_copy_from_buffer(dest, src_mapped, 0, PAGE_SIZE);
    kunmap(src_mapped);
    pop_cli(int_flag);
}

void page_copy_from_buffer(struct page* dest, const void* src, size_t offset,
                           size_t nbytes) {
    ASSERT(offset + nbytes <= PAGE_SIZE);
    bool int_flag = push_cli();
    unsigned char* dest_mapped = kmap_page(dest);
    memcpy(dest_mapped + offset, src, nbytes);
    kunmap(dest_mapped);
    pop_cli(int_flag);
}

void page_copy_to_buffer(struct page* src, void* dest, size_t offset,
                         size_t nbytes) {
    ASSERT(offset + nbytes <= PAGE_SIZE);
    bool int_flag = push_cli();
    unsigned char* src_mapped = kmap_page(src);
    memcpy(dest, src_mapped + offset, nbytes);
    kunmap(src_mapped);
    pop_cli(int_flag);
}

struct page* pages_get(struct page* pages, size_t index) {
    for (struct page* page = pages; page; page = page->next) {
        ASSERT(page->flags & PAGE_ALLOCATED);
        if (page->next)
            ASSERT(page->index < page->next->index);
        if (page->index == index)
            return page;
        if (page->index > index)
            return NULL;
    }
    return NULL;
}

struct page* pages_alloc_at(struct page** pages, size_t index) {
    struct page* prev = NULL;
    for (struct page* page = *pages; page; page = page->next) {
        ASSERT(page->flags & PAGE_ALLOCATED);
        if (page->next)
            ASSERT(page->index < page->next->index);
        if (page->index == index)
            return ERR_PTR(-EEXIST);
        if (page->index > index)
            break;
        prev = page;
    }

    struct page* page = page_alloc();
    if (IS_ERR(page))
        return page;
    page->index = index;
    if (prev) {
        page->next = prev->next;
        prev->next = page;
    } else {
        page->next = *pages;
        *pages = page;
    }

    return page;
}

struct page* pages_split_off(struct page** pages, size_t index) {
    struct page* page = *pages;
    while (page) {
        struct page* next = page->next;
        if (next && index <= next->index)
            break;
        page = next;
    }
    if (!page) {
        *pages = NULL;
        return NULL;
    }
    struct page* split = page->next;
    page->next = NULL;
    for (page = split; page; page = page->next)
        page->index -= index;
    return split;
}

void pages_free(struct page** pages, struct page* page) {
    if (!page)
        return;
    struct page* prev = NULL;
    struct page* it = *pages;
    for (; it && it != page; it = it->next)
        prev = it;
    ASSERT(it);
    if (prev)
        prev->next = page->next;
    else
        *pages = page->next;
    page_free(page);
}

bool pages_truncate(struct page** pages, size_t index) {
    struct page* split = pages_split_off(pages, index);
    bool freed = split != NULL;
    pages_clear(&split);
    return freed;
}

void pages_clear(struct page** pages) {
    struct page* page = *pages;
    while (page) {
        struct page* next = page->next;
        page_free(page);
        page = next;
    }
    *pages = NULL;
}

void memory_get_stats(struct memory_stats* out_stats) {
    *out_stats = (struct memory_stats){
        .total_kibibytes = (total_pages << PAGE_SHIFT) / 1024,
        .free_kibibytes = (free_pages << PAGE_SHIFT) / 1024,
    };
}
