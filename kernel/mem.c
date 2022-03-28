#include "mem.h"
#include "api/err.h"
#include "api/mman.h"
#include "api/syscall.h"
#include "asm_wrapper.h"
#include "boot_defs.h"
#include "kmalloc.h"
#include "kprintf.h"
#include "lock.h"
#include "multiboot.h"
#include "panic.h"
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

static ssize_t physical_page_bitmap_find_first_set(void) {
    for (size_t i = 0; i < physical_page_bitmap_len; ++i) {
        int b = __builtin_ffs(physical_page_bitmap[i]);
        if (b > 0) // b == 0 if physical_page_bitmap[i] == 0
            return (i << 5) | (b - 1);
    }
    return -ENOMEM;
}

static uintptr_t alloc_physical_page(void) {
    mutex_lock(&physical_page_lock);

    ssize_t first_set = physical_page_bitmap_find_first_set();
    if (IS_ERR(first_set)) {
        mutex_unlock(&physical_page_lock);
        return first_set;
    }

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

static volatile page_directory* current_page_directory(void) {
    return (volatile page_directory*)0xfffff000;
}

static volatile page_table* get_page_table(size_t pd_idx) {
    KASSERT(pd_idx < 1024);
    return (volatile page_table*)(0xffc00000 + PAGE_SIZE * pd_idx);
}

// quickmap temporarily maps a physical page to the fixed virtual address,
// which is at the final page of the kernel page directory

#define QUICKMAP_VADDR (KERNEL_VADDR + PAGE_SIZE * 1023)

static uintptr_t quickmap(uintptr_t paddr, uint32_t flags) {
    volatile page_table* pt = get_page_table(KERNEL_PDE_IDX);
    volatile page_table_entry* pte = pt->entries + 1023;
    KASSERT(pte->raw == 0);
    pte->raw = paddr | flags;
    pte->present = true;
    flush_tlb_single(QUICKMAP_VADDR);
    return QUICKMAP_VADDR;
}

static void unquickmap(void) {
    volatile page_table* pt = get_page_table(KERNEL_PDE_IDX);
    volatile page_table_entry* pte = pt->entries + 1023;
    KASSERT(pte->present);
    pte->raw = 0;
    flush_tlb_single(QUICKMAP_VADDR);
}

static page_table* clone_page_table(const volatile page_table* src,
                                    uintptr_t src_vaddr) {
    page_table* dst = kaligned_alloc(PAGE_SIZE, sizeof(page_table));
    if (!dst)
        return ERR_PTR(-ENOMEM);

    for (size_t i = 0; i < 1024; ++i) {
        if (!src->entries[i].present) {
            dst->entries[i].raw = 0;
            continue;
        }

        uintptr_t dst_physical_addr = alloc_physical_page();
        if (IS_ERR(dst_physical_addr))
            return ERR_CAST(dst_physical_addr);

        dst->entries[i].raw = dst_physical_addr | (src->entries[i].raw & 0xfff);

        uintptr_t mapped_dst_page = quickmap(dst_physical_addr, MEM_WRITE);
        memcpy((void*)mapped_dst_page, (void*)(src_vaddr + PAGE_SIZE * i),
               PAGE_SIZE);
        unquickmap();
    }
    return dst;
}

static volatile page_table* get_or_create_page_table(uintptr_t vaddr) {
    size_t pd_idx = vaddr >> 22;

    volatile page_directory_entry* pde =
        current_page_directory()->entries + pd_idx;
    bool created = false;
    if (!pde->present) {
        pde->raw = alloc_physical_page();
        if (IS_ERR(pde->raw))
            return ERR_CAST(pde->raw);

        pde->present = pde->write = pde->user = true;
        created = true;
    }

    volatile page_table* pt = get_page_table(vaddr >> 22);
    if (created)
        memset((void*)pt, 0, sizeof(page_table));

    return pt;
}

static volatile page_table_entry* get_pte(uintptr_t vaddr) {
    size_t pd_idx = vaddr >> 22;
    volatile page_directory_entry* pde =
        current_page_directory()->entries + pd_idx;
    if (!pde->present)
        return NULL;

    volatile page_table* pt = get_page_table(pd_idx);
    return pt->entries + ((vaddr >> 12) & 0x3ff);
}

static uintptr_t get_physical_addr(uintptr_t vaddr) {
    const volatile page_table_entry* pte = get_pte(vaddr);
    KASSERT(pte && pte->present);
    return (pte->raw & ~0xfff) | (vaddr & 0xfff);
}

static int map_page_anywhere(uintptr_t vaddr, uint32_t flags) {
    volatile page_table* pt = get_or_create_page_table(vaddr);
    if (IS_ERR(pt))
        return PTR_ERR(pt);

    volatile page_table_entry* pte = pt->entries + ((vaddr >> 12) & 0x3ff);
    KASSERT(!pte->present);

    uintptr_t physical_page_addr = alloc_physical_page();
    if (IS_ERR(physical_page_addr))
        return physical_page_addr;

    pte->raw = physical_page_addr | flags;
    pte->present = true;

    flush_tlb_single(vaddr);
    return 0;
}

static int map_page_at_fixed_physical_addr(uintptr_t vaddr, uintptr_t paddr,
                                           uint32_t flags) {
    volatile page_table* pt = get_or_create_page_table(vaddr);
    if (IS_ERR(pt))
        return PTR_ERR(pt);

    volatile page_table_entry* pte = pt->entries + ((vaddr >> 12) & 0x3ff);
    KASSERT(!pte->present);
    pte->raw = paddr | flags;
    pte->present = true;
    flush_tlb_single(vaddr);

    return 0;
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
    KASSERT(paddr == get_physical_addr((uintptr_t)current_page_directory()));
}

uintptr_t mem_clone_current_page_directory_and_get_physical_addr(void) {
    volatile page_directory* src = current_page_directory();
    page_directory* dst = kaligned_alloc(PAGE_SIZE, sizeof(page_directory));
    if (!dst)
        return -ENOMEM;

    uintptr_t pd_paddr = get_physical_addr((uintptr_t)dst);

    // userland
    for (size_t i = 0; i < KERNEL_PDE_IDX; ++i) {
        if (!src->entries[i].present) {
            dst->entries[i].raw = 0;
            continue;
        }

        volatile page_table* pt = get_page_table(i);
        page_table* cloned_pt = clone_page_table(pt, i * 0x400000);
        if (IS_ERR(cloned_pt))
            return PTR_ERR(cloned_pt);

        dst->entries[i].raw =
            (uintptr_t)get_physical_addr((uintptr_t)cloned_pt) |
            (src->entries[i].raw & 0xfff);
    }

    // kernel
    memcpy(dst->entries + KERNEL_PDE_IDX,
           (void*)(src->entries + KERNEL_PDE_IDX),
           (1022 - KERNEL_PDE_IDX) * sizeof(page_directory_entry));

    // recursive
    page_directory_entry* last_entry = dst->entries + 1023;
    last_entry->raw = pd_paddr;
    last_entry->present = last_entry->write = true;

    return pd_paddr;
}

void mem_init(const multiboot_info_t* mb_info) {
    kprintf("Kernel page directory: P0x%x\n",
            get_physical_addr((uintptr_t)current_page_directory()));

    uintptr_t lower_bound, upper_bound;
    get_available_physical_addr_bounds(mb_info, &lower_bound, &upper_bound);
    kprintf("Available physical memory address space: P0x%x - P0x%x\n",
            lower_bound, upper_bound);

    // In the current setup, kernel image (including 1MiB offset) has to fit in
    // single page table (< 4MiB), and last page is reserved for quickmap
    KASSERT(lower_bound <= 1023 * PAGE_SIZE);

    physical_page_bitmap_len = div_ceil(upper_bound, PAGE_SIZE * 32);
    KASSERT(physical_page_bitmap_len <= PHYSICAL_PAGE_BITMAP_MAX_LEN);

    set_bits_for_available_physical_pages(mb_info, lower_bound, upper_bound);

    mutex_init(&physical_page_lock);
}

int mem_map_to_private_anonymous_region(uintptr_t vaddr, uintptr_t size,
                                        uint16_t flags) {
    KASSERT((vaddr % PAGE_SIZE) == 0);
    KASSERT((size % PAGE_SIZE) == 0);

    for (uintptr_t offset = 0; offset < size; offset += PAGE_SIZE) {
        int rc = map_page_anywhere(vaddr + offset, flags);
        if (IS_ERR(rc))
            return rc;
    }

    return 0;
}

int mem_map_to_shared_physical_range(uintptr_t vaddr, uintptr_t paddr,
                                     uintptr_t size, uint16_t flags) {
    KASSERT((vaddr % PAGE_SIZE) == 0);
    KASSERT((paddr % PAGE_SIZE) == 0);
    KASSERT((size % PAGE_SIZE) == 0);

    for (uintptr_t offset = 0; offset < size; offset += PAGE_SIZE) {
        int rc = map_page_at_fixed_physical_addr(vaddr + offset, paddr + offset,
                                                 flags);
        if (IS_ERR(rc))
            return rc;
    }

    return 0;
}

uint16_t mem_prot_to_flags(int prot) {
    uint32_t flags = MEM_USER;
    if (prot & PROT_WRITE)
        flags |= MEM_WRITE;
    return flags;
}
