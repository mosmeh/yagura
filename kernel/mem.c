#include "mem.h"
#include "asm_wrapper.h"
#include "boot_defs.h"
#include "kmalloc.h"
#include "kprintf.h"
#include "lock.h"
#include "multiboot.h"
#include "system.h"
#include <common/extra.h>
#include <common/string.h>
#include <stdalign.h>
#include <stdbool.h>

#define MAX_NUM_PHYSICAL_PAGES (1024 * 1024)
#define PHYSICAL_PAGE_BITMAP_MAX_LEN (MAX_NUM_PHYSICAL_PAGES / 32)

static size_t physical_page_bitmap_len;
static uint32_t physical_page_bitmap[PHYSICAL_PAGE_BITMAP_MAX_LEN];
static mutex physical_page_lock;

static void physical_page_bitmap_set(size_t i) {
    KASSERT((i >> 5) < physical_page_bitmap_len);
    physical_page_bitmap[i >> 5] |= 1 << (i & 31);
}

static void physical_page_bitmap_clear(size_t i) {
    KASSERT((i >> 5) < physical_page_bitmap_len);
    physical_page_bitmap[i >> 5] &= ~(1 << (i & 31));
}

static size_t physical_page_bitmap_find_first_set(void) {
    for (size_t i = 0; i < physical_page_bitmap_len; ++i) {
        int b = __builtin_ffs(physical_page_bitmap[i]);
        if (b > 0) // b == 0 if physical_page_bitmap[i] == 0
            return (i << 5) | (b - 1);
    }
    KPANIC("Out of physical memory");
}

static uintptr_t alloc_physical_page(void) {
    mutex_lock(&physical_page_lock);

    size_t first_set = physical_page_bitmap_find_first_set();
    physical_page_bitmap_clear(first_set);

    mutex_unlock(&physical_page_lock);
    return first_set * PAGE_SIZE;
}

typedef union page_directory_entry {
    struct {
        bool present : 1;
        bool write : 1;
        bool user : 1;
        bool write_through : 1;
        bool cache_disable : 1;
        bool accessed : 1;
        bool ignored1 : 1;
        bool page_size : 1;
        uint8_t ignored2 : 4;
        uint32_t page_table_addr : 20;
    };
    uint32_t raw;
} __attribute__((packed)) page_directory_entry;

typedef struct page_directory {
    alignas(PAGE_SIZE) page_directory_entry entries[1024];
} page_directory;

typedef union page_table_entry {
    struct {
        bool present : 1;
        bool write : 1;
        bool user : 1;
        bool write_through : 1;
        bool cache_disable : 1;
        bool accessed : 1;
        bool dirty : 1;
        bool pat : 1;
        bool global : 1;
        uint8_t ignored : 3;
        uint32_t physical_page_addr : 20;
    };
    uint32_t raw;
} __attribute__((packed)) page_table_entry;

typedef struct page_table {
    alignas(PAGE_SIZE) page_table_entry entries[1024];
} page_table;

volatile page_directory* mem_current_page_directory(void) {
    return (volatile page_directory*)0xfffff000;
}

// temporarily maps a physical page to the fixed virtual address,
// which is at the final page of the kernel page directory
static uintptr_t quickmap(uintptr_t paddr, uint32_t flags) {
    volatile page_table* pt = mem_get_page_table(KERNEL_PDE_IDX);
    volatile page_table_entry* pte = pt->entries + 1023;
    KASSERT(pte->raw == 0);
    pte->raw = paddr | flags;
    pte->present = true;
    flush_tlb();
    return KERNEL_VADDR + PAGE_SIZE * 1023;
}

static void unquickmap(void) {
    volatile page_table* pt = mem_get_page_table(KERNEL_PDE_IDX);
    volatile page_table_entry* pte = pt->entries + 1023;
    KASSERT(pte->present);
    pte->raw = 0;
    flush_tlb();
}

static page_table* clone_page_table(const volatile page_table* src,
                                    uintptr_t src_vaddr) {
    page_table* dst =
        (page_table*)kaligned_alloc(PAGE_SIZE, sizeof(page_table));
    for (size_t i = 0; i < 1024; ++i) {
        if (!src->entries[i].present) {
            dst->entries[i].raw = 0;
            continue;
        }

        uintptr_t dst_physical_addr = alloc_physical_page();
        dst->entries[i].raw = dst_physical_addr | (src->entries[i].raw & 0xfff);

        uintptr_t mapped_dst_page = quickmap(dst_physical_addr, MEM_WRITE);
        memcpy((void*)mapped_dst_page, (void*)(src_vaddr + PAGE_SIZE * i),
               PAGE_SIZE);
        unquickmap();
    }
    return dst;
}

static volatile page_table_entry* get_pte(uintptr_t vaddr) {
    size_t pd_idx = vaddr >> 22;
    volatile page_directory_entry* pde =
        mem_current_page_directory()->entries + pd_idx;
    if (!pde->present)
        return NULL;

    volatile page_table* pt = mem_get_page_table(pd_idx);
    return pt->entries + ((vaddr >> 12) & 0x3ff);
}

extern unsigned char kernel_end[];

static void get_heap_mem_bounds(const multiboot_info_t* mb_info,
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

static void
set_bits_for_available_physical_pages(const multiboot_info_t* mb_info,
                                      uintptr_t lower_bound,
                                      uintptr_t upper_bound) {
    if (!(mb_info->flags & MULTIBOOT_INFO_MEM_MAP)) {
        for (size_t i = div_ceil(lower_bound, PAGE_SIZE);
             i < upper_bound / PAGE_SIZE; ++i)
            physical_page_bitmap_set(i);
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
            physical_page_bitmap_set(i);
    }

    size_t num_physical_pages = 0;
    for (size_t i = 0; i < physical_page_bitmap_len; ++i) {
        for (size_t b = 0; b < 32; ++b)
            num_physical_pages += (physical_page_bitmap[i] >> b) & 1;
    }
    kprintf("#Physical pages: %u (%u MiB)\n", num_physical_pages,
            num_physical_pages * PAGE_SIZE / 0x100000);
}

void mem_switch_page_directory(uintptr_t paddr) {
    __asm__ volatile("mov %0, %%cr3" ::"r"(paddr));
    KASSERT(paddr ==
            mem_get_physical_addr((uintptr_t)mem_current_page_directory()));
}

volatile page_table* mem_get_page_table(size_t pd_idx) {
    KASSERT(pd_idx < 1024);
    return (volatile page_table*)(0xffc00000 + PAGE_SIZE * pd_idx);
}

uintptr_t mem_get_physical_addr(uintptr_t vaddr) {
    const volatile page_table_entry* pte = get_pte(vaddr);
    KASSERT(pte && pte->present);
    return (pte->raw & ~0xfff) | (vaddr & 0xfff);
}

page_directory* mem_clone_page_directory(void) {
    volatile page_directory* src = mem_current_page_directory();
    page_directory* dst =
        (page_directory*)kaligned_alloc(PAGE_SIZE, sizeof(page_directory));

    // userland
    for (size_t i = 0; i < KERNEL_PDE_IDX; ++i) {
        if (!src->entries[i].present) {
            dst->entries[i].raw = 0;
            continue;
        }
        volatile page_table* pt = mem_get_page_table(i);
        uintptr_t cloned_pt_vaddr =
            (uintptr_t)clone_page_table(pt, i * 0x400000);
        dst->entries[i].raw =
            (uintptr_t)mem_get_physical_addr(cloned_pt_vaddr) |
            (src->entries[i].raw & 0xfff);
    }

    // kernel
    memcpy(dst->entries + KERNEL_PDE_IDX,
           (void*)(src->entries + KERNEL_PDE_IDX),
           (1022 - KERNEL_PDE_IDX) * sizeof(page_directory_entry));

    // recursive
    page_directory_entry* last_entry = dst->entries + 1023;
    last_entry->raw = mem_get_physical_addr((uintptr_t)dst);
    last_entry->present = last_entry->write = true;

    return dst;
}

volatile page_table_entry* mem_map_virtual_addr_to_any_page(uintptr_t vaddr,
                                                            uint32_t flags) {
    size_t pd_idx = vaddr >> 22;
    volatile page_directory_entry* pde =
        mem_current_page_directory()->entries + pd_idx;
    bool new_page_table = false;
    if (!pde->present) {
        pde->raw = alloc_physical_page();
        pde->present = pde->write = pde->user = true;
        new_page_table = true;
        flush_tlb();
    }

    volatile page_table* pt = mem_get_page_table(pd_idx);
    if (new_page_table)
        memset((void*)pt, 0, sizeof(page_table));
    volatile page_table_entry* pte = pt->entries + ((vaddr >> 12) & 0x3ff);
    if (!pte->present) {
        pte->raw = alloc_physical_page() | flags;
        pte->present = true;
        flush_tlb();
    }

    return pte;
}

void mem_map_virtual_addr_range_to_any_pages(uintptr_t start, uintptr_t end,
                                             uint32_t flags) {
    uintptr_t page_start = round_down(start, PAGE_SIZE);
    uintptr_t page_end = round_down(end - 1, PAGE_SIZE);

    for (uintptr_t vaddr = page_start; vaddr <= page_end; vaddr += PAGE_SIZE)
        mem_map_virtual_addr_to_any_page(vaddr, flags);
}

void mem_init(const multiboot_info_t* mb_info) {
    kprintf("Kernel page directory: P0x%x\n",
            mem_get_physical_addr((uintptr_t)mem_current_page_directory()));

    uintptr_t lower_bound, upper_bound;
    get_heap_mem_bounds(mb_info, &lower_bound, &upper_bound);

    // In the current setup, kernel image (including 1MiB offset) has to fit in
    // single page table (< 4MiB), and last page is reserved for quickmap
    KASSERT(lower_bound <= 1023 * PAGE_SIZE);

    physical_page_bitmap_len = div_ceil(upper_bound, PAGE_SIZE * 32);
    KASSERT(physical_page_bitmap_len <= PHYSICAL_PAGE_BITMAP_MAX_LEN);

    set_bits_for_available_physical_pages(mb_info, lower_bound, upper_bound);

    mutex_init(&physical_page_lock);
}
