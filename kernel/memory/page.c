#include "memory.h"
#include "private.h"
#include <common/extra.h>
#include <common/string.h>
#include <kernel/api/sys/types.h>
#include <kernel/kmsg.h>
#include <kernel/multiboot.h>
#include <kernel/panic.h>
#include <kernel/system.h>
#include <stdbool.h>

#define BITMAP_INDEX(i) ((i) / 32)
#define BITMAP_MASK(i) (1U << ((i) & 31))
#define BITMAP_MAX_LEN BITMAP_INDEX(MAX_NUM_PAGES)

static size_t pfn_end; // Maximum physical frame number + 1
static atomic_uint bitmap[BITMAP_MAX_LEN];
static atomic_size_t cached_free_index;

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
    size_t i = cached_free_index;
    for (size_t offset = 0; offset < BITMAP_INDEX(pfn_end); ++offset) {
        for (;;) {
            uint32_t v = bitmap[i];
            int b = __builtin_ffs(v);
            if (b == 0) // v == 0
                break;
            uint32_t new_v = v & ~BITMAP_MASK(b - 1);
            if (atomic_compare_exchange_weak(&bitmap[i], &v, new_v)) {
                cached_free_index = i;
                return i * 32 + (b - 1);
            }
        }
        i = (i + 1) % BITMAP_INDEX(pfn_end);
    }
    return -ENOMEM;
}

static void print_range(const char* type, uintptr_t start, uintptr_t end) {
    kprintf("page: P0x%08x - P0x%08x (%4u MiB) %s\n", start, end,
            (end - start) / 0x100000, type);
}

static void detect_memory(const multiboot_info_t* mb_info) {
    // We don't know the size of the physical memory yet.
    // Set the maximum possible value so that we can modify the entire bitmap.
    pfn_end = MAX_NUM_PAGES;

    ASSERT(KERNEL_VIRT_ADDR < (uintptr_t)kernel_end &&
           (uintptr_t)kernel_end <= KERNEL_IMAGE_END);
    uintptr_t kernel_phys_end = (uintptr_t)kernel_end - KERNEL_VIRT_ADDR;
    uintptr_t available_start = kernel_phys_end;
    uintptr_t available_end = available_start;

    if (mb_info->flags & MULTIBOOT_INFO_MEM_MAP) {
        uint32_t num_entries =
            mb_info->mmap_length / sizeof(multiboot_memory_map_t);
        const multiboot_memory_map_t* entry =
            (const void*)(mb_info->mmap_addr + KERNEL_VIRT_ADDR);

        for (uint32_t i = 0; i < num_entries; ++i, ++entry) {
            uint64_t entry_start = entry->addr;
            uint64_t entry_end = entry->addr + entry->len;

            // This is a 32-bit system. Ignore entries beyond 4 GiB.
            if (entry_start > UINTPTR_MAX || entry_end > UINTPTR_MAX)
                continue;

            const char* type_str = "unknown";
            switch (entry->type) {
            case MULTIBOOT_MEMORY_AVAILABLE:
                type_str = "available";
                break;
            case MULTIBOOT_MEMORY_RESERVED:
                type_str = "reserved";
                break;
            case MULTIBOOT_MEMORY_ACPI_RECLAIMABLE:
                type_str = "ACPI reclaimable";
                break;
            case MULTIBOOT_MEMORY_NVS:
                type_str = "NVS";
                break;
            case MULTIBOOT_MEMORY_BADRAM:
                type_str = "bad RAM";
                break;
            }

            print_range(type_str, entry_start, entry_end);

            if (entry->type != MULTIBOOT_MEMORY_AVAILABLE)
                continue;

            if (entry_start < available_start)
                entry_start = available_start;

            if (entry_start >= entry_end)
                continue;

            if (available_end < entry_end)
                available_end = entry_end;

            for (size_t i = DIV_CEIL(entry_start, PAGE_SIZE);
                 i < entry_end >> PAGE_SHIFT; ++i)
                bitmap_set(i);
        }
    } else {
        kprint("page: no memory map provided by bootloader\n");

        available_end =
            MAX(available_start, mb_info->mem_upper * 0x400 + 0x100000);

        for (size_t i = DIV_CEIL(available_start, PAGE_SIZE);
             i < available_end >> PAGE_SHIFT; ++i)
            bitmap_set(i);

        print_range("available", available_start, available_end);
    }

    print_range("kernel", 0, kernel_phys_end);

    if (mb_info->flags & MULTIBOOT_INFO_MODS) {
        const multiboot_module_t* mod =
            (const void*)(mb_info->mods_addr + KERNEL_VIRT_ADDR);
        for (uint32_t i = 0; i < mb_info->mods_count; ++i) {
            print_range("module", mod->mod_start, mod->mod_end);
            for (size_t i = mod->mod_start >> PAGE_SHIFT;
                 i < DIV_CEIL(mod->mod_end, PAGE_SIZE); ++i)
                bitmap_clear(i);
            ++mod;
        }
    }

    pfn_end = available_end >> PAGE_SHIFT;
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
    kprintf("page: %u pages (%u MiB) available\n", total_pages,
            (total_pages << PAGE_SHIFT) / 0x100000);
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
    unsigned char* mapped_page = kmap_page(page);
    memset(mapped_page + offset, value, nbytes);
    kunmap(mapped_page);
}

void page_copy(struct page* dest, struct page* src) {
    void* src_mapped = kmap_page(src);
    page_copy_from_buffer(dest, src_mapped, 0, PAGE_SIZE);
    kunmap(src_mapped);
}

void page_copy_from_buffer(struct page* dest, const void* src, size_t offset,
                           size_t nbytes) {
    ASSERT(offset + nbytes <= PAGE_SIZE);
    unsigned char* dest_mapped = kmap_page(dest);
    memcpy(dest_mapped + offset, src, nbytes);
    kunmap(dest_mapped);
}

void page_copy_to_buffer(struct page* src, void* dest, size_t offset,
                         size_t nbytes) {
    ASSERT(offset + nbytes <= PAGE_SIZE);
    unsigned char* src_mapped = kmap_page(src);
    memcpy(dest, src_mapped + offset, nbytes);
    kunmap(src_mapped);
}

struct page* pages_first(const struct tree* tree) {
    struct tree_node* node = tree_first(tree);
    if (!node)
        return NULL;
    return CONTAINER_OF(node, struct page, tree_node);
}

struct page* pages_next(const struct page* page) {
    struct tree_node* node = tree_next(&page->tree_node);
    if (!node)
        return NULL;
    return CONTAINER_OF(node, struct page, tree_node);
}

struct page* pages_get(const struct tree* tree, size_t index) {
    struct tree_node* node = tree->root;
    while (node) {
        struct page* page = CONTAINER_OF(node, struct page, tree_node);
        if (index < page->index)
            node = node->left;
        else if (index > page->index)
            node = node->right;
        else
            return page;
    }
    return NULL;
}

struct page* pages_alloc_at(struct tree* tree, size_t index) {
    struct tree_node** new_node = &tree->root;
    struct tree_node* parent = NULL;
    while (*new_node) {
        parent = *new_node;
        struct page* page = CONTAINER_OF(parent, struct page, tree_node);
        if (index < page->index)
            new_node = &parent->left;
        else if (index > page->index)
            new_node = &parent->right;
        else
            return ERR_PTR(-EEXIST);
    }

    struct page* page = page_alloc();
    if (IS_ERR(ASSERT(page)))
        return page;
    page->index = index;

    *new_node = &page->tree_node;
    tree_insert(tree, parent, *new_node);

    return page;
}

void pages_split_off(struct tree* src, struct tree* dst, size_t index) {
    for (;;) {
        struct tree_node* node = tree_last(src);
        if (!node)
            break;
        struct page* page = CONTAINER_OF(node, struct page, tree_node);
        if (page->index < index)
            break;
        tree_remove(src, node);
        page->index -= index;

        struct tree_node** new_node = &dst->root;
        struct tree_node* parent = NULL;
        while (*new_node) {
            parent = *new_node;
            struct page* dst_page =
                CONTAINER_OF(parent, struct page, tree_node);
            if (page->index < dst_page->index)
                new_node = &parent->left;
            else if (page->index > dst_page->index)
                new_node = &parent->right;
            else
                PANIC("Duplicate page index");
        }
        *new_node = node;
        tree_insert(dst, parent, *new_node);
    }
}

bool pages_truncate(struct tree* tree, size_t index) {
    bool truncated = false;
    for (;;) {
        struct tree_node* node = tree_last(tree);
        if (!node)
            break;
        struct page* page = CONTAINER_OF(node, struct page, tree_node);
        if (page->index < index)
            break;
        tree_remove(tree, node);
        page_free(page);
        truncated = true;
    }
    return truncated;
}

void pages_clear(struct tree* tree) {
    for (;;) {
        struct tree_node* node = tree->root;
        if (!node)
            break;
        tree_remove(tree, node);
        struct page* page = CONTAINER_OF(node, struct page, tree_node);
        page_free(page);
    }
}

void memory_get_stats(struct memory_stats* out_stats) {
    *out_stats = (struct memory_stats){
        .total_kibibytes = (total_pages << PAGE_SHIFT) / 1024,
        .free_kibibytes = (free_pages << PAGE_SHIFT) / 1024,
    };
}
