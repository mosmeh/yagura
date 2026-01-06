#include "private.h"
#include <common/string.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/memory/memory.h>
#include <kernel/task/task.h>

// Page directory
struct pagemap {
    alignas(PAGE_SIZE) uint32_t entries[1024];
};

#define PAGE_TABLE_FLAGS_MASK ((1 << PAGE_SHIFT) - 1)

static size_t pde_index(uintptr_t virt_addr) { return virt_addr >> PD_SHIFT; }

static size_t pte_index(uintptr_t virt_addr) {
    return (virt_addr >> PAGE_SHIFT) & ((1 << (PD_SHIFT - PAGE_SHIFT)) - 1);
}

// Returns the physical address of the page table.
static uintptr_t ensure_page_table(struct pagemap* pagemap,
                                   uintptr_t virt_addr) {
    uint32_t* pde = pagemap->entries + pde_index(virt_addr);
    if (*pde & PTE_PRESENT)
        return *pde & ~PAGE_TABLE_FLAGS_MASK;

    ssize_t pfn = page_alloc_raw();
    if (IS_ERR(pfn))
        return pfn;

    uintptr_t phys_addr = (size_t)pfn << PAGE_SHIFT;

    void* page_table = kmap(phys_addr);
    memset(page_table, 0, PAGE_SIZE);
    kunmap(page_table);

    *pde = phys_addr | PTE_PRESENT | PTE_WRITE | PTE_USER;

    return phys_addr;
}

extern unsigned char kmap_page_table_start[];

static uint32_t* kmap_page_table =
    (uint32_t*)((uintptr_t)kmap_page_table_start + KERNEL_IMAGE_START);

static size_t kmap_pte_index(size_t local_index) {
    return (size_t)cpu_get_id() * KMAP_MAX_NUM_PER_CPU + local_index;
}

static uintptr_t kmap_addr(size_t local_index) {
    return KMAP_START + (kmap_pte_index(local_index) << PAGE_SHIFT);
}

void* kmap(uintptr_t phys_addr) {
    ASSERT(phys_addr);
    ASSERT(phys_addr % PAGE_SIZE == 0);

    bool int_flag = interrupts_enabled();
    disable_interrupts();

    struct kmap_ctrl* kmap = &cpu_get_current()->kmap;
    size_t index = kmap->num_mapped++;
    ASSERT(index < KMAP_MAX_NUM_PER_CPU);
    ASSERT(!kmap->phys_addrs[index]);

    if (int_flag)
        ASSERT(index == 0);
    if (index == 0)
        kmap->prev_int_flag = int_flag;

    kmap->phys_addrs[index] = phys_addr;

    uint32_t* pte = kmap_page_table + kmap_pte_index(index);
    ASSERT(!(*pte & PTE_PRESENT));
    *pte = phys_addr | PTE_PRESENT | PTE_WRITE;

    uintptr_t kaddr = kmap_addr(index);
    flush_tlb_single(kaddr);
    return (void*)kaddr;
}

void* kmap_page(struct page* page) {
    ASSERT(page);
    return kmap(page_to_pfn(page) << PAGE_SHIFT);
}

void kunmap(void* addr) {
    ASSERT(!interrupts_enabled());
    ASSERT(addr);

    size_t offset = (uintptr_t)addr - kmap_addr(0);
    ASSERT(offset % PAGE_SIZE == 0);
    size_t index = offset >> PAGE_SHIFT;
    ASSERT(index < KMAP_MAX_NUM_PER_CPU);

    struct kmap_ctrl* kmap = &cpu_get_current()->kmap;
    ASSERT(kmap->num_mapped == index + 1);
    kmap->phys_addrs[index] = 0;
    --kmap->num_mapped;

    uint32_t* pte = kmap_page_table + kmap_pte_index(index);
    ASSERT(*pte & PTE_PRESENT);
    *pte = 0;
    flush_tlb_single((uintptr_t)addr);

    if (kmap->num_mapped == 0) {
        if (kmap->prev_int_flag)
            enable_interrupts();
        kmap->prev_int_flag = false;
    }
}

extern unsigned char kernel_page_directory_start[];

struct pagemap* kernel_pagemap =
    (void*)((uintptr_t)kernel_page_directory_start + KERNEL_IMAGE_START);

uintptr_t virt_to_phys(void* virt_addr) {
    uintptr_t vaddr = (uintptr_t)virt_addr;

    uint32_t pde = kernel_pagemap->entries[pde_index(vaddr)];
    ASSERT(pde & PTE_PRESENT);

    uint32_t* pt = kmap(pde & ~PAGE_TABLE_FLAGS_MASK);
    uint32_t pte = pt[pte_index(vaddr)];
    ASSERT(pte & PTE_PRESENT);
    uintptr_t phys_addr =
        (pte & ~PAGE_TABLE_FLAGS_MASK) | (vaddr & PAGE_TABLE_FLAGS_MASK);
    kunmap(pt);

    return phys_addr;
}

#define KERNEL_PDE_START_INDEX (KERNEL_IMAGE_START >> PD_SHIFT)

struct pagemap* pagemap_create(void) {
    // Populate page directory entries for kernel space so that
    // all page directories share the same kernel space
    for (size_t i = KERNEL_PDE_START_INDEX;
         i < ARRAY_SIZE(kernel_pagemap->entries); ++i) {
        uintptr_t phys_addr = ensure_page_table(kernel_pagemap, i << PD_SHIFT);
        if (IS_ERR(phys_addr))
            return ERR_PTR(phys_addr);
    }
    struct pagemap* pagemap =
        kaligned_alloc(alignof(struct pagemap), sizeof(struct pagemap));
    if (!pagemap)
        return ERR_PTR(-ENOMEM);

    // Userland will have no mappings initially
    memset(pagemap, 0, KERNEL_PDE_START_INDEX * sizeof(uint32_t));

    // Kernel space mappings are shared
    memcpy(pagemap->entries + KERNEL_PDE_START_INDEX,
           kernel_pagemap->entries + KERNEL_PDE_START_INDEX,
           (ARRAY_SIZE(pagemap->entries) - KERNEL_PDE_START_INDEX) *
               sizeof(uint32_t));

    return pagemap;
}

void pagemap_destroy(struct pagemap* pagemap) {
    if (!pagemap)
        return;

    ASSERT(pagemap != kernel_pagemap);
    ASSERT(pagemap != current->vm->pagemap);

    for (size_t i = 0; i < KERNEL_PDE_START_INDEX; ++i) {
        uint32_t entry = pagemap->entries[i];
        if (entry & PTE_PRESENT)
            page_free_raw(entry >> PAGE_SHIFT);
    }

    kfree(pagemap);
}

void pagemap_switch(struct pagemap* to) { write_cr3(virt_to_phys(to)); }

static void flush_tlb_global(struct pagemap* pagemap, uintptr_t virt_addr,
                             size_t size) {
    ASSERT((virt_addr % PAGE_SIZE) == 0);
    ASSERT((size % PAGE_SIZE) == 0);
    if (size == 0)
        return;

    bool is_user = is_user_range((void*)virt_addr, size);

    struct ipi_message* msg = NULL;
    if (smp_active) {
        uint8_t current_cpu_id = cpu_get_id();
        for (size_t i = 0; i < num_cpus; ++i) {
            if (i == current_cpu_id)
                continue;
            struct cpu* cpu = cpus[i];
            struct task* task = cpu->current_task;
            if (task && is_user && task->vm->pagemap != pagemap) {
                // This CPU does not share the same page directory with us.
                continue;
            }
            if (task == cpu->idle_task) {
                // Idle task does not do anything that requires TLB consistency.
                // Just schedule a TLB flush before its next task switch.
                cpu_unicast_message_coalesced(cpu, IPI_MESSAGE_FLUSH_TLB,
                                              false);
                continue;
            }
            if (msg) {
                // Allows the reference count to be zero here because
                // other CPUs might have already processed the message.
                refcount_inc_allowing_zero(&msg->refcount);
            } else {
                msg = cpu_alloc_message();
                *msg = (struct ipi_message){
                    .type = IPI_MESSAGE_FLUSH_TLB_RANGE,
                    .refcount = REFCOUNT_INIT_ONE,
                    .flush_tlb_range = {.virt_addr = virt_addr, .size = size},
                };
            }
            cpu_unicast_message_queued(cpu, msg, true);
        }
    }

    if (!is_user || pagemap == current->vm->pagemap) {
        // Flush this CPU's TLB while other CPUs are flushing theirs
        for (uintptr_t addr = virt_addr; addr < virt_addr + size;
             addr += PAGE_SIZE)
            flush_tlb_single(addr);
    }

    if (msg) {
        // Wait for other CPUs to finish processing FLUSH_TLB_RANGE
        while (refcount_get(&msg->refcount) > 0)
            cpu_pause();
        cpu_free_message(msg);
    }
}

static void flush_tlb_local(struct pagemap* pagemap, uintptr_t virt_addr) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    bool is_user = is_user_address((void*)virt_addr);
    if (!is_user || pagemap == current->vm->pagemap)
        flush_tlb_single(virt_addr);
}

NODISCARD static int map(struct pagemap* pagemap, uintptr_t virt_addr,
                         size_t pfn, uint16_t flags) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    ASSERT(!(flags & ~PAGE_TABLE_FLAGS_MASK));

    uintptr_t pt_phys_addr = ensure_page_table(pagemap, virt_addr);
    if (IS_ERR(pt_phys_addr))
        return PTR_ERR(pt_phys_addr);

    uint32_t* page_table = kmap(pt_phys_addr);
    page_table[pte_index(virt_addr)] =
        (pfn << PAGE_SHIFT) | flags | PTE_PRESENT;
    kunmap(page_table);

    return 0;
}

int pagemap_map(struct pagemap* pagemap, uintptr_t virt_addr, size_t pfn,
                size_t npages, uint16_t flags) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    if (npages == 0)
        return 0;
    int rc = 0;
    size_t i = 0;
    for (; i < npages; ++i) {
        rc = map(pagemap, virt_addr + (i << PAGE_SHIFT), pfn + i, flags);
        if (IS_ERR(rc))
            break;
    }
    flush_tlb_global(pagemap, virt_addr, i << PAGE_SHIFT);
    return rc;
}

int pagemap_map_local(struct pagemap* pagemap, uintptr_t virt_addr, size_t pfn,
                      uint16_t flags) {
    int rc = map(pagemap, virt_addr, pfn, flags);
    if (IS_ERR(rc))
        return rc;
    flush_tlb_local(pagemap, virt_addr);
    return 0;
}

static void unmap(struct pagemap* pagemap, uintptr_t virt_addr) {
    ASSERT(virt_addr % PAGE_SIZE == 0);

    uint32_t pde = pagemap->entries[pde_index(virt_addr)];
    if (!(pde & PTE_PRESENT))
        return;

    uint32_t* page_table = kmap(pde & ~PAGE_TABLE_FLAGS_MASK);
    page_table[pte_index(virt_addr)] = 0;
    kunmap(page_table);
}

void pagemap_unmap(struct pagemap* pagemap, uintptr_t virt_addr,
                   size_t npages) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    if (npages == 0)
        return;
    for (size_t i = 0; i < npages; ++i)
        unmap(pagemap, virt_addr + (i << PAGE_SHIFT));
    flush_tlb_global(pagemap, virt_addr, npages << PAGE_SHIFT);
}

void pagemap_unmap_local(struct pagemap* pagemap, uintptr_t virt_addr) {
    unmap(pagemap, virt_addr);
    flush_tlb_local(pagemap, virt_addr);
}
