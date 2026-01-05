#include "private.h"
#include <common/string.h>
#include <kernel/cpu.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/task/task.h>

#define PTE_FLAGS_MASK ((1UL << PAGE_SHIFT) - 1)

#define PAGE_TABLE_LEVELS 4
#define BITS_PER_LEVEL 9
#define TO_CANONICAL(addr) ((uintptr_t)((intptr_t)((addr) << 16) >> 16))

#define LEVEL_MASK ((1UL << BITS_PER_LEVEL) - 1)
#define LEVEL_SHIFT(level) (PAGE_SHIFT + BITS_PER_LEVEL * (level))
#define LEVEL_SIZE(level) (1UL << LEVEL_SHIFT(level))
#define LEVEL_INDEX(vaddr, level) (((vaddr) >> LEVEL_SHIFT(level)) & LEVEL_MASK)

// Level Table
// 0     PT
// 1     PD
// 2     PDPT
// 3     PML4

static volatile void* get_page_table(uintptr_t vaddr, int level) {
    ASSERT(0 <= level && level < PAGE_TABLE_LEVELS);

    // Start address of the recursive mapping
    uintptr_t addr = TO_CANONICAL(RECURSIVE_MAPPING_INDEX *
                                  LEVEL_SIZE(PAGE_TABLE_LEVELS - 1));

    // Skip PAGE_TABLE_LEVELS below the target level
    for (int l = 1; l <= level; ++l)
        addr += RECURSIVE_MAPPING_INDEX * LEVEL_SIZE(PAGE_TABLE_LEVELS - 1 - l);

    // Add offsets for PAGE_TABLE_LEVELS above the target level
    for (int l = PAGE_TABLE_LEVELS - 1; l > level; --l)
        addr += LEVEL_INDEX(vaddr, l) * LEVEL_SIZE(l - level - 1);

    return (volatile void*)addr;
}

static volatile uint64_t* get_pte(uintptr_t virt_addr) {
    for (int level = PAGE_TABLE_LEVELS - 1;; --level) {
        volatile uint64_t* table = get_page_table(virt_addr, level);
        volatile uint64_t* entry = table + LEVEL_INDEX(virt_addr, level);
        if (level == 0)
            return entry;
        if (!(*entry & PTE_PRESENT))
            return NULL;
    }
}

static volatile uint64_t* ensure_pte(uintptr_t virt_addr) {
    for (int level = PAGE_TABLE_LEVELS - 1;; --level) {
        volatile uint64_t* table = get_page_table(virt_addr, level);
        volatile uint64_t* entry = table + LEVEL_INDEX(virt_addr, level);
        if (level == 0)
            return entry;
        if (*entry & PTE_PRESENT)
            continue;
        ssize_t pfn = page_alloc_raw();
        if (IS_ERR(pfn))
            return ERR_PTR(pfn);
        *entry = (pfn << PAGE_SHIFT) | PTE_PRESENT | PTE_WRITE | PTE_USER;
        table = get_page_table(virt_addr, level - 1);
        flush_tlb_single((uintptr_t)table);
        memset((void*)table, 0, PAGE_SIZE);
    }
}

static struct page_table* current_page_table(void) {
    struct vm* vm = current->vm;
    ASSERT(vm);
    struct page_table* pt = vm->page_table;
    ASSERT(pt);
    return pt;
}

uintptr_t virt_to_phys(void* virt_addr) {
    uintptr_t addr = (uintptr_t)virt_addr;
    const volatile uint64_t* pte = get_pte(addr);
    ASSERT(pte);
    ASSERT(*pte & PTE_PRESENT);
    return (*pte & ~PTE_FLAGS_MASK) | (addr & PTE_FLAGS_MASK);
}

struct page_table* page_table_create(void) {
    // Populate page directory entries for kernel space so that
    // all page directories share the same kernel space
    size_t count = (KERNEL_VIRT_END - KERNEL_VIRT_START) /
                   LEVEL_SIZE(PAGE_TABLE_LEVELS - 1);
    for (size_t i = 0; i < count; ++i) {
        uintptr_t virt_addr =
            KERNEL_VIRT_START + i * LEVEL_SIZE(PAGE_TABLE_LEVELS - 1);
        volatile uint64_t* pte = ensure_pte(virt_addr);
        if (IS_ERR(ASSERT(pte)))
            return ERR_CAST(pte);
    }

    uint64_t* dst = kaligned_alloc(PAGE_SIZE, PAGE_SIZE);
    if (!dst)
        return ERR_PTR(-ENOMEM);

    // userland
    memset(dst, 0, 256 * sizeof(uint64_t));

    // kernel
    memcpy(dst + 256, (uint64_t*)kernel_page_table + 256,
           256 * sizeof(uint64_t));

    // recursive
    dst[RECURSIVE_MAPPING_INDEX] = virt_to_phys(dst) | PTE_WRITE | PTE_PRESENT;

    return (struct page_table*)dst;
}

extern unsigned char kernel_page_table_start[];

struct page_table* kernel_page_table =
    (void*)((uintptr_t)kernel_page_table_start + KERNEL_IMAGE_ADDR);

void page_table_destroy(struct page_table* pt) {
    if (!pt)
        return;

    ASSERT(pt != kernel_page_table);
    ASSERT(pt != current_page_table());

    /*for (size_t i = 0; i < KERNEL_PDE_IDX; ++i) {
        if (pd->entries[i] & PTE_PRESENT)
            page_free_raw(pd->entries[i] >> PAGE_SHIFT);
    }*/

    kfree(pt);
}

void page_table_switch(struct page_table* to) {
    uintptr_t phys_addr = virt_to_phys(to);
    write_cr3(phys_addr);
    ASSERT(phys_addr ==
           virt_to_phys((void*)get_page_table(0, PAGE_TABLE_LEVELS - 1)));
}

static void flush_tlb_range(uintptr_t virt_addr, size_t size) {
    ASSERT((virt_addr % PAGE_SIZE) == 0);
    ASSERT((size % PAGE_SIZE) == 0);

    SCOPED_DISABLE_INTERRUPTS();

    struct ipi_message* msg = NULL;
    if (smp_active) {
        bool is_user = is_user_range((void*)virt_addr, size);
        uint8_t current_cpu_id = cpu_get_id();
        for (size_t i = 0; i < num_cpus; ++i) {
            if (i == current_cpu_id)
                continue;
            struct cpu* cpu = cpus[i];
            struct task* task = cpu->current_task;
            if (task && is_user && task->vm != current->vm) {
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

    // Flush this CPU's TLB while other CPUs are flushing theirs
    for (uintptr_t addr = virt_addr; addr < virt_addr + size; addr += PAGE_SIZE)
        flush_tlb_single(addr);

    // Wait for other CPUs to finish processing FLUSH_TLB_RANGE
    if (msg) {
        while (refcount_get(&msg->refcount) > 0)
            cpu_pause();
        cpu_free_message(msg);
    }
}

NODISCARD static int map(uintptr_t virt_addr, size_t pfn, uint64_t flags) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    ASSERT(!(flags & ~PTE_FLAGS_MASK));
    volatile uint64_t* pte = ensure_pte(virt_addr);
    if (IS_ERR(ASSERT(pte)))
        return PTR_ERR(pte);
    *pte = (pfn << PAGE_SHIFT) | flags | PTE_PRESENT;
    return 0;
}

int page_table_map(uintptr_t virt_addr, size_t pfn, size_t npages,
                   uint64_t flags) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    for (size_t i = 0; i < npages; ++i) {
        int rc = map(virt_addr + (i << PAGE_SHIFT), pfn + i, flags);
        if (IS_ERR(rc))
            return rc;
    }
    flush_tlb_range(virt_addr, npages << PAGE_SHIFT);
    return 0;
}

int page_table_map_local(uintptr_t virt_addr, size_t pfn, uint64_t flags) {
    int rc = map(virt_addr, pfn, flags);
    if (IS_ERR(rc))
        return rc;
    flush_tlb_single(virt_addr);
    return 0;
}

static void unmap(uintptr_t virt_addr) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    volatile uint64_t* pte = get_pte(virt_addr);
    if (pte)
        *pte = 0;
}

void page_table_unmap(uintptr_t virt_addr, size_t npages) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    for (size_t i = 0; i < npages; ++i)
        unmap(virt_addr + (i << PAGE_SHIFT));
    flush_tlb_range(virt_addr, npages << PAGE_SHIFT);
}

void page_table_unmap_local(uintptr_t virt_addr) {
    unmap(virt_addr);
    flush_tlb_single(virt_addr);
}

static uintptr_t kmap_addr(size_t index) {
    return KMAP_START + (((size_t)cpu_get_id() * MAX_NUM_KMAPS_PER_CPU + index)
                         << PAGE_SHIFT);
}

void* kmap(uintptr_t phys_addr) {
    ASSERT(phys_addr);
    ASSERT(phys_addr % PAGE_SIZE == 0);

    bool int_flag = interrupts_enabled();
    disable_interrupts();

    struct kmap_ctrl* kmap = &cpu_get_current()->kmap;
    size_t index = kmap->num_mapped++;
    ASSERT(index < MAX_NUM_KMAPS_PER_CPU);
    ASSERT(!kmap->phys_addrs[index]);

    if (int_flag)
        ASSERT(index == 0);
    if (index == 0)
        kmap->prev_int_flag = int_flag;

    kmap->phys_addrs[index] = phys_addr;

    uintptr_t kaddr = kmap_addr(index);
    volatile uint64_t* pte = ensure_pte(kaddr);
    ASSERT(pte);
    *pte = phys_addr | PTE_WRITE | PTE_PRESENT;
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
    ASSERT(index < MAX_NUM_KMAPS_PER_CPU);

    struct kmap_ctrl* kmap = &cpu_get_current()->kmap;
    ASSERT(kmap->num_mapped == index + 1);
    kmap->phys_addrs[index] = 0;
    --kmap->num_mapped;

    volatile uint64_t* pte = get_pte((uintptr_t)addr);
    ASSERT(pte);
    ASSERT(*pte & PTE_PRESENT);
    *pte = 0;
    flush_tlb_single((uintptr_t)addr);

    if (kmap->num_mapped == 0) {
        if (kmap->prev_int_flag)
            enable_interrupts();
        kmap->prev_int_flag = false;
    }
}
