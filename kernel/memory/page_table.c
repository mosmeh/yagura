#include <kernel/arch/system.h>
#include <kernel/cpu.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/phys.h>
#include <kernel/task/task.h>

void* kmap_page(struct page* page) {
    ASSERT(page);
    return kmap(page_to_pfn(page) << PAGE_SHIFT);
}

static void flush_tlb_global(struct pagemap* pagemap, uintptr_t virt_addr,
                             size_t size) {
    ASSERT((virt_addr % PAGE_SIZE) == 0);
    ASSERT((size % PAGE_SIZE) == 0);
    if (size == 0)
        return;

    bool is_user = is_user_range((void*)virt_addr, size);

    struct ipi_message* msg = NULL;
    if (arch_smp_active()) {
        unsigned long current_cpu_id = cpu_get_id();
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
            arch_flush_tlb_single(addr);
    }

    if (msg) {
        // Wait for other CPUs to finish processing FLUSH_TLB_RANGE
        while (refcount_get(&msg->refcount) > 0)
            cpu_relax();
        cpu_free_message(msg);
    }
}

static void flush_tlb_local(struct pagemap* pagemap, uintptr_t virt_addr) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    bool is_user = is_user_address((void*)virt_addr);
    if (!is_user || pagemap == current->vm->pagemap)
        arch_flush_tlb_single(virt_addr);
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
    flush_tlb_global(pagemap, virt_addr, i << PAGE_SHIFT);
    return rc;
}

int pagemap_map_local(struct pagemap* pagemap, uintptr_t virt_addr, size_t pfn,
                      unsigned flags) {
    int rc = arch_map_page(pagemap, virt_addr, pfn, flags);
    if (IS_ERR(rc))
        return rc;
    flush_tlb_local(pagemap, virt_addr);
    return 0;
}

void pagemap_unmap(struct pagemap* pagemap, uintptr_t virt_addr,
                   size_t npages) {
    ASSERT(virt_addr % PAGE_SIZE == 0);
    if (npages == 0)
        return;
    for (size_t i = 0; i < npages; ++i)
        arch_unmap_page(pagemap, virt_addr + (i << PAGE_SHIFT));
    flush_tlb_global(pagemap, virt_addr, npages << PAGE_SHIFT);
}

void pagemap_unmap_local(struct pagemap* pagemap, uintptr_t virt_addr) {
    arch_unmap_page(pagemap, virt_addr);
    flush_tlb_local(pagemap, virt_addr);
}
