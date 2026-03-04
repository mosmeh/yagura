#include <kernel/arch/system.h>
#include <kernel/cpu.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/phys.h>
#include <kernel/memory/vm.h>
#include <kernel/task/task.h>

void* kmap_page(struct page* page, unsigned flags) {
    ASSERT_PTR(page);
    return kmap(page_to_phys(page), flags);
}

static void invalidate_tlb_local(struct pagemap* pagemap, uintptr_t virt_addr,
                                 size_t npages) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    if (npages == 0)
        return;
    if (is_user_address((void*)virt_addr)) {
        SCOPED_DISABLE_INTERRUPTS();
        if (cpu_get_current()->active_pagemap != pagemap)
            return;
    }
    for (size_t i = 0; i < npages; ++i)
        arch_invalidate_tlb_page(virt_addr + (i << PAGE_SHIFT));
}

static void invalidate_tlb_global(struct pagemap* pagemap, uintptr_t virt_addr,
                                  size_t npages) {
    ASSERT((virt_addr % PAGE_SIZE) == 0);
    if (npages == 0)
        return;

    bool is_user = is_user_range((void*)virt_addr, npages << PAGE_SHIFT);

    struct ipi_message* msg = NULL;
    if (arch_smp_active()) {
        unsigned long current_cpu_id = cpu_get_id();
        for (size_t i = 0; i < num_cpus; ++i) {
            if (i == current_cpu_id)
                continue;
            struct cpu* cpu = cpus[i];
            if (is_user) {
                struct pagemap* active_pagemap = cpu->active_pagemap;
                if (active_pagemap && active_pagemap != pagemap) {
                    // This CPU does not share the same page table with the
                    // current CPU.
                    continue;
                }
            }
            if (msg) {
                // Allows the reference count to be zero here because
                // other CPUs might have already processed the message.
                refcount_inc_allowing_zero(&msg->refcount);
            } else {
                msg = cpu_alloc_message();
                *msg = (struct ipi_message){
                    .type = IPI_MESSAGE_INVALIDATE_TLB_RANGE,
                    .refcount = REFCOUNT_INIT_ONE,
                    .invalidate_tlb_range = {.virt_addr = virt_addr,
                                             .npages = npages},
                };
            }
            cpu_unicast_message_queued(cpu, msg, true);
        }
    }

    // Invalidate this CPU's TLB while other CPUs are invalidating theirs
    invalidate_tlb_local(pagemap, virt_addr, npages);

    if (msg) {
        // Wait for other CPUs to finish processing INVALIDATE_TLB_RANGE
        while (refcount_get(&msg->refcount) > 0)
            cpu_relax();
        cpu_free_message(msg);
    }
}

int pagemap_map(struct pagemap* pagemap, uintptr_t virt_addr, size_t pfn,
                size_t npages, unsigned flags) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    if (npages == 0)
        return 0;
    int rc = 0;
    size_t i = 0;
    for (; i < npages; ++i) {
        rc = arch_map_page(pagemap, virt_addr + (i << PAGE_SHIFT), pfn + i,
                           flags);
        if (IS_ERR(rc))
            break;
    }
    invalidate_tlb_global(pagemap, virt_addr, i);
    return rc;
}

int pagemap_map_local(struct pagemap* pagemap, uintptr_t virt_addr, size_t pfn,
                      size_t npages, unsigned flags) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    if (npages == 0)
        return 0;
    int rc = 0;
    size_t i = 0;
    for (; i < npages; ++i) {
        rc = arch_map_page(pagemap, virt_addr + (i << PAGE_SHIFT), pfn + i,
                           flags);
        if (IS_ERR(rc))
            break;
    }
    invalidate_tlb_local(pagemap, virt_addr, i);
    return rc;
}

static void unmap_pages(struct pagemap* pagemap, uintptr_t virt_addr,
                        size_t npages) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    for (size_t i = 0; i < npages; ++i)
        arch_unmap_page(pagemap, virt_addr + (i << PAGE_SHIFT));
}

void pagemap_unmap(struct pagemap* pagemap, uintptr_t virt_addr,
                   size_t npages) {
    unmap_pages(pagemap, virt_addr, npages);
    invalidate_tlb_global(pagemap, virt_addr, npages);
}

void pagemap_unmap_local(struct pagemap* pagemap, uintptr_t virt_addr,
                         size_t npages) {
    unmap_pages(pagemap, virt_addr, npages);
    invalidate_tlb_local(pagemap, virt_addr, npages);
}

void pagemap_switch(struct pagemap* pagemap) {
    SCOPED_DISABLE_INTERRUPTS();
    cpu_get_current()->active_pagemap = pagemap;
    arch_switch_pagemap(pagemap);
}
