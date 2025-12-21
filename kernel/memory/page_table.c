#include "private.h"
#include <common/string.h>
#include <kernel/cpu.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/task.h>

#define PTE_FLAGS_MASK 0xfff

struct page_directory {
    alignas(PAGE_SIZE) uint32_t entries[1024];
};

struct page_table {
    alignas(PAGE_SIZE) uint32_t entries[1024];
};

static struct page_directory* current_page_directory(void) {
    struct vm* vm = current->vm;
    ASSERT(vm);
    struct page_directory* pd = vm->page_directory;
    ASSERT(pd);
    return pd;
}

static volatile struct page_table* get_page_table_from_index(size_t index) {
    ASSERT(index < 1024);
    return (volatile struct page_table*)(0xffc00000 + PAGE_SIZE * index);
}

static volatile struct page_table*
get_or_create_page_table(uintptr_t virt_addr) {
    size_t pd_idx = virt_addr >> 22;

    uint32_t* pde = current_page_directory()->entries + pd_idx;
    bool created = false;
    if (!(*pde & PTE_PRESENT)) {
        ssize_t pfn = page_alloc_raw();
        if (IS_ERR(pfn))
            return ERR_PTR(pfn);
        *pde = (pfn << PAGE_SHIFT) | PTE_WRITE | PTE_USER | PTE_PRESENT;
        created = true;
    }

    volatile struct page_table* pt = get_page_table_from_index(pd_idx);
    if (created)
        memset((void*)pt, 0, sizeof(struct page_table));

    return pt;
}

static volatile uint32_t* get_pte(uintptr_t virt_addr) {
    size_t pd_idx = virt_addr >> 22;
    uint32_t pde = current_page_directory()->entries[pd_idx];
    if (!(pde & PTE_PRESENT))
        return NULL;

    volatile struct page_table* pt = get_page_table_from_index(pd_idx);
    return pt->entries + ((virt_addr >> PAGE_SHIFT) & 0x3ff);
}

static volatile uint32_t* get_or_create_pte(uintptr_t virt_addr) {
    volatile struct page_table* pt = get_or_create_page_table(virt_addr);
    if (IS_ERR(ASSERT(pt)))
        return ERR_CAST(pt);
    return pt->entries + ((virt_addr >> PAGE_SHIFT) & 0x3ff);
}

uintptr_t virt_to_phys(void* virt_addr) {
    uintptr_t addr = (uintptr_t)virt_addr;
    const volatile uint32_t* pte = get_pte(addr);
    ASSERT(pte);
    ASSERT(*pte & PTE_PRESENT);
    return (*pte & ~PTE_FLAGS_MASK) | (addr & PTE_FLAGS_MASK);
}

struct page_directory* page_directory_create(void) {
    // Populate page directory entries for kernel space so that
    // all page directories share the same kernel space
    for (uintptr_t virt_addr = KERNEL_VIRT_ADDR; virt_addr < KERNEL_VM_END;
         virt_addr += 1024 << PAGE_SHIFT) {
        volatile struct page_table* pt = get_or_create_page_table(virt_addr);
        if (IS_ERR(ASSERT(pt)))
            return ERR_CAST(pt);
    }

    struct page_directory* dst = kaligned_alloc(alignof(struct page_directory),
                                                sizeof(struct page_directory));
    if (!dst)
        return ERR_PTR(-ENOMEM);

    // userland
    memset(dst->entries, 0, KERNEL_PDE_IDX * sizeof(uint32_t));

    // kernel
    memcpy(dst->entries + KERNEL_PDE_IDX,
           kernel_page_directory->entries + KERNEL_PDE_IDX,
           (1023 - KERNEL_PDE_IDX) * sizeof(uint32_t));

    // recursive
    dst->entries[1023] = virt_to_phys(dst) | PTE_WRITE | PTE_PRESENT;

    return dst;
}

extern unsigned char kernel_page_directory_start[];

struct page_directory* kernel_page_directory =
    (struct page_directory*)((uintptr_t)kernel_page_directory_start +
                             KERNEL_VIRT_ADDR);

void page_directory_destroy(struct page_directory* pd) {
    if (!pd)
        return;

    ASSERT(pd != kernel_page_directory);
    ASSERT(pd != current_page_directory());

    for (size_t i = 0; i < KERNEL_PDE_IDX; ++i) {
        if (pd->entries[i] & PTE_PRESENT)
            page_free_raw(pd->entries[i] >> PAGE_SHIFT);
    }

    kfree(pd);
}

void page_directory_switch(struct page_directory* to) {
    uintptr_t phys_addr = virt_to_phys(to);
    write_cr3(phys_addr);
    ASSERT(phys_addr == virt_to_phys((void*)0xfffff000));
}

static void flush_tlb_range(uintptr_t virt_addr, size_t size) {
    ASSERT((virt_addr % PAGE_SIZE) == 0);
    ASSERT((size % PAGE_SIZE) == 0);

    bool int_flag = push_cli();

    struct ipi_message* msg = NULL;
    if (smp_active) {
        if (is_kernel_address((void*)virt_addr)) {
            msg = cpu_alloc_message();
            *msg = (struct ipi_message){
                .type = IPI_MESSAGE_FLUSH_TLB,
                .flush_tlb = {.virt_addr = virt_addr, .size = size},
                .refcount = REFCOUNT_INIT(num_cpus - 1),
            };
            cpu_broadcast_message(msg);
        } else {
            ASSERT(is_user_range((void*)virt_addr, size));
            uint8_t cpu_id = cpu_get_id();

            // If the address is userland, we only need to flush TLBs of CPUs
            // that is in the same vm as the current task
            for (size_t i = 0; i < num_cpus; ++i) {
                if (i == cpu_id)
                    continue;
                struct cpu* cpu = cpus[i];
                struct task* task = cpu->current_task;
                if (!task)
                    continue;
                if (task->vm != current->vm)
                    continue;
                if (!msg) {
                    msg = cpu_alloc_message();
                    *msg = (struct ipi_message){
                        .type = IPI_MESSAGE_FLUSH_TLB,
                        .flush_tlb = {.virt_addr = virt_addr, .size = size},
                    };
                }
                refcount_inc(&msg->refcount);
                cpu_unicast_message(cpu, msg);
            }
        }
    }

    // While other CPUs are flushing TLBs, we can flush this CPU's TLB
    for (uintptr_t addr = virt_addr; addr < virt_addr + size; addr += PAGE_SIZE)
        flush_tlb_single(addr);

    // Wait for other CPUs to finish flushing TLBs
    if (msg) {
        while (refcount_get(&msg->refcount) > 0)
            cpu_pause();
        cpu_free_message(msg);
    }

    pop_cli(int_flag);
}

NODISCARD static int map(uintptr_t virt_addr, size_t pfn, uint16_t flags) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    ASSERT(!(flags & ~PTE_FLAGS_MASK));
    volatile uint32_t* pte = get_or_create_pte(virt_addr);
    if (IS_ERR(ASSERT(pte)))
        return PTR_ERR(pte);
    *pte = (pfn << PAGE_SHIFT) | flags | PTE_PRESENT;
    return 0;
}

int page_table_map(uintptr_t virt_addr, size_t pfn, size_t npages,
                   uint16_t flags) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    for (size_t i = 0; i < npages; ++i) {
        int rc = map(virt_addr + (i << PAGE_SHIFT), pfn + i, flags);
        if (IS_ERR(rc))
            return rc;
    }
    flush_tlb_range(virt_addr, npages << PAGE_SHIFT);
    return 0;
}

int page_table_map_local(uintptr_t virt_addr, size_t pfn, uint16_t flags) {
    int rc = map(virt_addr, pfn, flags);
    if (IS_ERR(rc))
        return rc;
    flush_tlb_single(virt_addr);
    return 0;
}

static void unmap(uintptr_t virt_addr) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    volatile uint32_t* pte = get_pte(virt_addr);
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
    return KMAP_START +
           ((cpu_get_id() * MAX_NUM_KMAPS_PER_CPU + index) << PAGE_SHIFT);
}

void* kmap(uintptr_t phys_addr) {
    ASSERT(phys_addr);
    ASSERT(phys_addr % PAGE_SIZE == 0);

    bool int_flag = push_cli();

    struct kmap_ctrl* kmap = &cpu_get_current()->kmap;
    size_t index = kmap->num_mapped++;
    ASSERT(index < MAX_NUM_KMAPS_PER_CPU);
    ASSERT(!kmap->phys_addrs[index]);

    if (int_flag)
        ASSERT(index == 0);
    if (index == 0)
        kmap->pushed_cli = int_flag;

    kmap->phys_addrs[index] = phys_addr;

    uintptr_t kaddr = kmap_addr(index);
    volatile uint32_t* pte = get_or_create_pte(kaddr);
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

    volatile uint32_t* pte = get_pte((uintptr_t)addr);
    ASSERT(pte);
    ASSERT(*pte & PTE_PRESENT);
    *pte = 0;
    flush_tlb_single((uintptr_t)addr);

    if (kmap->num_mapped == 0) {
        pop_cli(kmap->pushed_cli);
        kmap->pushed_cli = false;
    }
}
