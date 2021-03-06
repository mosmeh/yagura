#include "memory.h"
#include <common/extra.h>
#include <kernel/boot_defs.h>
#include <kernel/interrupts.h>
#include <kernel/kprintf.h>
#include <kernel/lock.h>
#include <kernel/panic.h>
#include <stdalign.h>
#include <string.h>

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

static page_directory* current_pd;

page_directory* paging_current_page_directory(void) { return current_pd; }

static volatile page_table* get_page_table_from_idx(size_t pd_idx) {
    ASSERT(pd_idx < 1024);
    return (volatile page_table*)(0xffc00000 + PAGE_SIZE * pd_idx);
}

static volatile page_table* get_or_create_page_table(uintptr_t vaddr) {
    size_t pd_idx = vaddr >> 22;

    page_directory_entry* pde = current_pd->entries + pd_idx;
    bool created = false;
    if (!pde->present) {
        pde->raw = page_allocator_alloc();
        if (IS_ERR(pde->raw))
            return ERR_CAST(pde->raw);

        pde->present = pde->write = pde->user = true;
        created = true;
    }

    volatile page_table* pt = get_page_table_from_idx(pd_idx);
    if (created)
        memset((void*)pt, 0, sizeof(page_table));

    return pt;
}

static volatile page_table_entry* get_pte(uintptr_t vaddr) {
    size_t pd_idx = vaddr >> 22;
    page_directory_entry* pde = current_pd->entries + pd_idx;
    if (!pde->present)
        return NULL;

    volatile page_table* pt = get_page_table_from_idx(pd_idx);
    return pt->entries + ((vaddr >> 12) & 0x3ff);
}

static volatile page_table_entry* get_or_create_pte(uintptr_t vaddr) {
    volatile page_table* pt = get_or_create_page_table(vaddr);
    if (IS_ERR(pt))
        return ERR_CAST(pt);
    return pt->entries + ((vaddr >> 12) & 0x3ff);
}

uintptr_t paging_virtual_to_physical_addr(uintptr_t vaddr) {
    const volatile page_table_entry* pte = get_pte(vaddr);
    ASSERT(pte && pte->present);
    return (pte->raw & ~0xfff) | (vaddr & 0xfff);
}

static int map_page_to_free_page(uintptr_t vaddr, uint32_t flags) {
    volatile page_table_entry* pte = get_or_create_pte(vaddr);
    if (IS_ERR(pte))
        return PTR_ERR(pte);
    ASSERT(!pte->present);

    uintptr_t physical_page_addr = page_allocator_alloc();
    if (IS_ERR(physical_page_addr))
        return physical_page_addr;

    pte->raw = physical_page_addr | flags;
    pte->present = true;

    flush_tlb_single(vaddr);
    return 0;
}

static int map_page_to_physical_addr(uintptr_t vaddr, uintptr_t paddr,
                                     uint32_t flags) {
    volatile page_table_entry* pte = get_or_create_pte(vaddr);
    if (IS_ERR(pte))
        return PTR_ERR(pte);
    ASSERT(!pte->present);

    page_allocator_ref_page(paddr);

    pte->raw = paddr | flags;
    pte->present = true;
    flush_tlb_single(vaddr);

    return 0;
}

static int copy_page_mapping(uintptr_t to_vaddr, uintptr_t from_vaddr,
                             uint32_t flags) {
    volatile page_table_entry* from_pte = get_pte(from_vaddr);
    ASSERT(from_pte && from_pte->present);

    volatile page_table_entry* to_pte = get_or_create_pte(to_vaddr);
    if (IS_ERR(to_pte))
        return PTR_ERR(to_pte);
    ASSERT(!to_pte->present);

    uintptr_t paddr = from_pte->raw & ~0xfff;
    page_allocator_ref_page(paddr);

    to_pte->raw = paddr | flags;
    to_pte->present = true;
    flush_tlb_single(to_vaddr);

    return 0;
}

static void unmap_page(uintptr_t vaddr) {
    volatile page_table_entry* pte = get_pte(vaddr);
    ASSERT(pte && pte->present);
    page_allocator_unref_page(pte->raw & ~0xfff);
    pte->raw = 0;
    flush_tlb_single(vaddr);
}

page_directory* paging_create_page_directory(void) {
    page_directory* dst = kaligned_alloc(PAGE_SIZE, sizeof(page_directory));
    if (!dst)
        return ERR_PTR(-ENOMEM);

    // kernel
    memcpy(dst->entries + KERNEL_PDE_IDX,
           (void*)(current_pd->entries + KERNEL_PDE_IDX),
           (1023 - KERNEL_PDE_IDX) * sizeof(page_directory_entry));

    // recursive
    page_directory_entry* last_entry = dst->entries + 1023;
    last_entry->raw = paging_virtual_to_physical_addr((uintptr_t)dst);
    last_entry->present = last_entry->write = true;

    return dst;
}

// quickmap temporarily maps a physical page to the fixed virtual address,
// which is at the final page of the kernel page directory

#define QUICKMAP_VADDR (KERNEL_VADDR + PAGE_SIZE * 1023)

// this is locked in paging_clone_current_page_directory
static mutex quickmap_lock;

static uintptr_t quickmap(uintptr_t paddr, uint32_t flags) {
    volatile page_table* pt = get_page_table_from_idx(KERNEL_PDE_IDX);
    volatile page_table_entry* pte = pt->entries + 1023;
    ASSERT(pte->raw == 0);
    pte->raw = paddr | flags;
    pte->present = true;
    flush_tlb_single(QUICKMAP_VADDR);
    return QUICKMAP_VADDR;
}

static void unquickmap(void) {
    volatile page_table* pt = get_page_table_from_idx(KERNEL_PDE_IDX);
    volatile page_table_entry* pte = pt->entries + 1023;
    ASSERT(pte->present);
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

        if (src->entries[i].raw & PAGE_SHARED) {
            dst->entries[i].raw = src->entries[i].raw;
            page_allocator_ref_page(src->entries[i].raw & ~0xfff);
            continue;
        }

        uintptr_t dst_physical_addr = page_allocator_alloc();
        if (IS_ERR(dst_physical_addr))
            return ERR_CAST(dst_physical_addr);

        dst->entries[i].raw = dst_physical_addr | (src->entries[i].raw & 0xfff);

        uintptr_t mapped_dst_page = quickmap(dst_physical_addr, PAGE_WRITE);
        memcpy((void*)mapped_dst_page, (void*)(src_vaddr + PAGE_SIZE * i),
               PAGE_SIZE);
        unquickmap();
    }
    return dst;
}

page_directory* paging_clone_current_page_directory(void) {
    page_directory* dst = paging_create_page_directory();
    if (IS_ERR(dst))
        return dst;

    // copy userland region

    mutex_lock(&quickmap_lock);

    for (size_t i = 0; i < KERNEL_PDE_IDX; ++i) {
        if (!current_pd->entries[i].present) {
            dst->entries[i].raw = 0;
            continue;
        }

        volatile page_table* pt = get_page_table_from_idx(i);
        page_table* cloned_pt = clone_page_table(pt, i * 0x400000);
        if (IS_ERR(cloned_pt)) {
            mutex_unlock(&quickmap_lock);
            return ERR_CAST(cloned_pt);
        }

        dst->entries[i].raw =
            paging_virtual_to_physical_addr((uintptr_t)cloned_pt) |
            (current_pd->entries[i].raw & 0xfff);
    }

    mutex_unlock(&quickmap_lock);

    return dst;
}

static void destroy_page_table(volatile page_table* pt) {
    for (size_t i = 0; i < 1024; ++i) {
        if (!pt->entries[i].present)
            continue;
        page_allocator_unref_page(pt->entries[i].raw & ~0xfff);
    }
}

void paging_destroy_current_page_directory(void) {
    for (size_t i = 0; i < KERNEL_PDE_IDX; ++i) {
        if (!current_pd->entries[i].present)
            continue;
        destroy_page_table(get_page_table_from_idx(i));
    }
}

void paging_switch_page_directory(page_directory* pd) {
    bool int_flag = push_cli();

    uintptr_t paddr = paging_virtual_to_physical_addr((uintptr_t)pd);
    write_cr3(paddr);
    current_pd = pd;
    ASSERT(paddr == paging_virtual_to_physical_addr(0xfffff000));

    pop_cli(int_flag);
}

range_allocator kernel_vaddr_allocator;

extern unsigned char kernel_page_directory[];

void paging_init(const multiboot_info_t* mb_info) {
    current_pd =
        (page_directory*)((uintptr_t)kernel_page_directory + KERNEL_VADDR);
    kprintf("Kernel page directory: P0x%x\n", (uintptr_t)kernel_page_directory);

    page_allocator_init(mb_info);
    ASSERT_OK(range_allocator_init(&kernel_vaddr_allocator, KERNEL_HEAP_START,
                                   KERNEL_HEAP_END));

    for (size_t addr = KERNEL_HEAP_START; addr < KERNEL_HEAP_END;
         addr += 1024 * PAGE_SIZE)
        ASSERT_OK(get_or_create_page_table(addr));
}

int paging_map_to_free_pages(uintptr_t vaddr, uintptr_t size, uint16_t flags) {
    ASSERT((vaddr % PAGE_SIZE) == 0);
    size = round_up(size, PAGE_SIZE);

    for (uintptr_t offset = 0; offset < size; offset += PAGE_SIZE) {
        int rc = map_page_to_free_page(vaddr + offset, flags);
        if (IS_ERR(rc))
            return rc;
    }

    return 0;
}

int paging_map_to_physical_range(uintptr_t vaddr, uintptr_t paddr,
                                 uintptr_t size, uint16_t flags) {
    ASSERT((vaddr % PAGE_SIZE) == 0);
    ASSERT((paddr % PAGE_SIZE) == 0);
    size = round_up(size, PAGE_SIZE);

    for (uintptr_t offset = 0; offset < size; offset += PAGE_SIZE) {
        int rc =
            map_page_to_physical_addr(vaddr + offset, paddr + offset, flags);
        if (IS_ERR(rc))
            return rc;
    }

    return 0;
}

int paging_copy_mapping(uintptr_t to_vaddr, uintptr_t from_vaddr,
                        uintptr_t size, uint16_t flags) {
    ASSERT((to_vaddr % PAGE_SIZE) == 0);
    ASSERT((from_vaddr % PAGE_SIZE) == 0);
    size = round_up(size, PAGE_SIZE);

    for (uintptr_t offset = 0; offset < size; offset += PAGE_SIZE) {
        int rc =
            copy_page_mapping(to_vaddr + offset, from_vaddr + offset, flags);
        if (IS_ERR(rc))
            return rc;
    }

    return 0;
}

void paging_unmap(uintptr_t vaddr, uintptr_t size) {
    ASSERT((vaddr % PAGE_SIZE) == 0);
    size = round_up(size, PAGE_SIZE);

    for (uintptr_t offset = 0; offset < size; offset += PAGE_SIZE)
        unmap_page(vaddr + offset);
}
