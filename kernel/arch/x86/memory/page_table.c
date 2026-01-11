#include <arch/memory.h>
#include <common/string.h>
#include <kernel/arch/x86/memory/page_table.h>
#include <kernel/cpu.h>
#include <kernel/interrupts.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/phys.h>
#include <kernel/task/task.h>

#define PAGE_TABLE_LEVELS 2
#define PAGE_TABLE_BITS_PER_LEVEL 10
#define PAGE_TABLE_FLAGS_MASK 0xfff

typedef uint32_t pte_t;

#define TOP_LEVEL (PAGE_TABLE_LEVELS - 1)
#define NUM_ENTRIES_PER_LEVEL (1UL << PAGE_TABLE_BITS_PER_LEVEL)

#define LEVEL_SHIFT(level) (PAGE_SHIFT + PAGE_TABLE_BITS_PER_LEVEL * (level))
#define LEVEL_INDEX(virt_addr, level)                                          \
    (((virt_addr) >> LEVEL_SHIFT(level)) & (NUM_ENTRIES_PER_LEVEL - 1))

#define ALIGNED_TO_TOP_LEVEL(addr)                                             \
    (((addr) & ((1UL << LEVEL_SHIFT(TOP_LEVEL)) - 1)) == 0)

STATIC_ASSERT(ALIGNED_TO_TOP_LEVEL(USER_VIRT_START));
STATIC_ASSERT(ALIGNED_TO_TOP_LEVEL(KERNEL_VIRT_START));

#define USER_START_INDEX LEVEL_INDEX(USER_VIRT_START, TOP_LEVEL)
#define USER_END_INDEX                                                         \
    (ALIGNED_TO_TOP_LEVEL(USER_VIRT_END) ? __USER_END_INDEX                    \
                                         : __USER_END_INDEX + 1)
#define __USER_END_INDEX LEVEL_INDEX(USER_VIRT_END, TOP_LEVEL)

#define KERNEL_START_INDEX LEVEL_INDEX(KERNEL_VIRT_START, TOP_LEVEL)
#define KERNEL_END_INDEX                                                       \
    (ALIGNED_TO_TOP_LEVEL(KERNEL_VIRT_END) ? __KERNEL_END_INDEX                \
                                           : __KERNEL_END_INDEX + 1)
#define __KERNEL_END_INDEX LEVEL_INDEX(KERNEL_VIRT_END, TOP_LEVEL)

struct pagemap {
    _Alignas(PAGE_SIZE) pte_t entries[NUM_ENTRIES_PER_LEVEL];
};

STATIC_ASSERT(sizeof(struct pagemap) == PAGE_SIZE);

static phys_addr_t get_page_table(struct pagemap* pagemap,
                                  uintptr_t virt_addr) {
    phys_addr_t phys_addr;
    for (int level = TOP_LEVEL; level > 0; --level) {
        pte_t* table = level < TOP_LEVEL ? kmap(phys_addr) : pagemap->entries;
        pte_t entry = table[LEVEL_INDEX(virt_addr, level)];
        if (level < TOP_LEVEL)
            kunmap(table);
        if (!(entry & PTE_PRESENT))
            return 0;
        phys_addr = entry & ~PAGE_TABLE_FLAGS_MASK;
    }
    return phys_addr;
}

// Returns the physical address of the lowest-level page table.
static phys_addr_t ensure_page_table(struct pagemap* pagemap,
                                     uintptr_t virt_addr) {
    phys_addr_t phys_addr;
    for (int level = TOP_LEVEL; level > 0; --level) {
        pte_t* table = level < TOP_LEVEL ? kmap(phys_addr) : pagemap->entries;
        pte_t* entry = table + LEVEL_INDEX(virt_addr, level);
        if (*entry & PTE_PRESENT) {
            phys_addr = *entry & ~PAGE_TABLE_FLAGS_MASK;
        } else {
            ssize_t pfn = page_alloc_raw();
            if (IS_ERR(pfn)) {
                if (level < TOP_LEVEL)
                    kunmap(table);
                return pfn;
            }
            phys_addr = (phys_addr_t)pfn << PAGE_SHIFT;
            void* new_table = kmap(phys_addr);
            memset(new_table, 0, PAGE_SIZE);
            kunmap(new_table);
            *entry = phys_addr | PTE_PRESENT | PTE_WRITE | PTE_USER;
        }
        if (level < TOP_LEVEL)
            kunmap(table);
    }
    return phys_addr;
}

extern unsigned char kmap_page_table_start[];

static pte_t* kmap_page_table =
    (pte_t*)((uintptr_t)kmap_page_table_start + KERNEL_IMAGE_START);

static size_t kmap_page_index(size_t local_index) {
    return (size_t)arch_cpu_get_id() * KMAP_MAX_NUM_PER_CPU + local_index;
}

static uintptr_t kmap_addr(size_t local_index) {
    return KMAP_START + (kmap_page_index(local_index) << PAGE_SHIFT);
}

void* kmap(phys_addr_t phys_addr) {
    ASSERT(phys_addr);
    ASSERT(phys_addr % PAGE_SIZE == 0);

    bool int_flag = arch_interrupts_enabled();
    arch_disable_interrupts();

    struct kmap_ctrl* kmap = &cpu_get_current()->kmap;
    size_t index = kmap->num_mapped++;
    ASSERT(index < KMAP_MAX_NUM_PER_CPU);
    ASSERT(!kmap->phys_addrs[index]);

    if (int_flag)
        ASSERT(index == 0);
    if (index == 0)
        kmap->prev_int_flag = int_flag;

    kmap->phys_addrs[index] = phys_addr;

    pte_t* pte = kmap_page_table + kmap_page_index(index);
    ASSERT(!(*pte & PTE_PRESENT));
    *pte = phys_addr | PTE_PRESENT | PTE_WRITE;

    uintptr_t kaddr = kmap_addr(index);
    arch_flush_tlb_single(kaddr);
    return (void*)kaddr;
}

void kunmap(void* addr) {
    ASSERT(!arch_interrupts_enabled());
    ASSERT(addr);

    size_t offset = (uintptr_t)addr - kmap_addr(0);
    ASSERT(offset % PAGE_SIZE == 0);
    size_t index = offset >> PAGE_SHIFT;
    ASSERT(index < KMAP_MAX_NUM_PER_CPU);

    struct kmap_ctrl* kmap = &cpu_get_current()->kmap;
    ASSERT(kmap->num_mapped == index + 1);
    kmap->phys_addrs[index] = 0;
    --kmap->num_mapped;

    pte_t* pte = kmap_page_table + kmap_page_index(index);
    ASSERT(*pte & PTE_PRESENT);
    *pte = 0;
    arch_flush_tlb_single((uintptr_t)addr);

    if (kmap->num_mapped == 0) {
        if (kmap->prev_int_flag)
            arch_enable_interrupts();
        kmap->prev_int_flag = false;
    }
}

extern unsigned char kernel_pml_top_start[];

struct pagemap* kernel_pagemap =
    (void*)((uintptr_t)kernel_pml_top_start + KERNEL_IMAGE_START);

phys_addr_t virt_to_phys(void* virt_addr) {
    uintptr_t vaddr = (uintptr_t)virt_addr;
    phys_addr_t pt_phys_addr = get_page_table(kernel_pagemap, vaddr);
    ASSERT(pt_phys_addr);
    pte_t* page_table = kmap(pt_phys_addr);
    pte_t entry = page_table[LEVEL_INDEX(vaddr, 0)];
    kunmap(page_table);
    ASSERT(entry & PTE_PRESENT);
    return (entry & ~PAGE_TABLE_FLAGS_MASK) | (vaddr & (PAGE_SIZE - 1));
}

struct pagemap* pagemap_create(void) {
    // Populate top-level page table entries for kernel space so that
    // all pagemaps share the same kernel space
    for (size_t i = KERNEL_START_INDEX; i < KERNEL_END_INDEX; ++i) {
        uintptr_t virt_addr = i << LEVEL_SHIFT(TOP_LEVEL);
        phys_addr_t phys_addr = ensure_page_table(kernel_pagemap, virt_addr);
        if (IS_ERR(phys_addr))
            return ERR_CAST(phys_addr);
    }

    struct pagemap* pagemap =
        kaligned_alloc(_Alignof(struct pagemap), sizeof(struct pagemap));
    if (!pagemap)
        return ERR_PTR(-ENOMEM);

    memset(pagemap->entries, 0, sizeof(pagemap->entries));

    // Kernel space mappings are shared
    memcpy(pagemap->entries + KERNEL_START_INDEX,
           kernel_pagemap->entries + KERNEL_START_INDEX,
           (KERNEL_END_INDEX - KERNEL_START_INDEX) * sizeof(pte_t));

    return pagemap;
}

static void free_table_recursive(const pte_t* table, int level) {
    size_t user_start;
    size_t user_end;
    if (level == TOP_LEVEL) {
        user_start = USER_START_INDEX;
        user_end = USER_END_INDEX;
    } else {
        user_start = 0;
        user_end = NUM_ENTRIES_PER_LEVEL;
    }
    for (size_t i = user_start; i < user_end; ++i) {
        pte_t entry = table[i];
        if (!(entry & PTE_PRESENT))
            continue;
        phys_addr_t phys_addr = entry & ~PAGE_TABLE_FLAGS_MASK;
        if (level > 1) {
            pte_t* child_table = kmap(phys_addr);
            free_table_recursive(child_table, level - 1);
            kunmap(child_table);
        }
        page_free_raw(phys_addr >> PAGE_SHIFT);
    }
}

void pagemap_destroy(struct pagemap* pagemap) {
    if (!pagemap)
        return;
    ASSERT(pagemap != kernel_pagemap);
    ASSERT(pagemap != current->vm->pagemap);
    free_table_recursive(pagemap->entries, TOP_LEVEL);
    kfree(pagemap);
}

void pagemap_switch(struct pagemap* to) { write_cr3(virt_to_phys(to)); }

static pte_t vm_flags_to_pte_flags(unsigned vm_flags) {
    pte_t pte_flags = PTE_PRESENT;
    if (vm_flags & VM_WRITE)
        pte_flags |= PTE_WRITE;
    if (vm_flags & VM_USER)
        pte_flags |= PTE_USER;
    else
        pte_flags |= PTE_GLOBAL;
    if (vm_flags & VM_WC)
        pte_flags |= PTE_PAT;
    return pte_flags;
}

int arch_map_page(struct pagemap* pagemap, uintptr_t virt_addr, size_t pfn,
                  unsigned flags) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    ASSERT(!(flags & ~PAGE_TABLE_FLAGS_MASK));

    phys_addr_t pt_phys_addr = ensure_page_table(pagemap, virt_addr);
    if (IS_ERR(pt_phys_addr))
        return pt_phys_addr;

    pte_t* page_table = kmap(pt_phys_addr);
    page_table[LEVEL_INDEX(virt_addr, 0)] =
        ((pte_t)pfn << PAGE_SHIFT) | vm_flags_to_pte_flags(flags);
    kunmap(page_table);

    return 0;
}

void arch_unmap_page(struct pagemap* pagemap, uintptr_t virt_addr) {
    ASSERT(virt_addr % PAGE_SIZE == 0);

    phys_addr_t pt_phys_addr = get_page_table(pagemap, virt_addr);
    if (!pt_phys_addr)
        return;

    pte_t* page_table = kmap(pt_phys_addr);
    page_table[LEVEL_INDEX(virt_addr, 0)] = 0;
    kunmap(page_table);
}
