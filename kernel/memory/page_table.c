#include "memory.h"
#include "private.h"
#include <common/string.h>
#include <kernel/cpu.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/task.h>

#define PTE_FLAGS_MASK 0xfff

typedef union {
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

typedef struct {
    alignas(PAGE_SIZE) page_table_entry entries[1024];
} page_table;

struct page_directory* current_page_directory(void) {
    if (!current)
        return kernel_page_directory;
    struct vm* vm = current->vm;
    ASSERT(vm);
    struct page_directory* pd = vm->page_directory;
    ASSERT(pd);
    return pd;
}

static volatile page_table* get_page_table_from_index(size_t index) {
    ASSERT(index < 1024);
    return (volatile page_table*)(0xffc00000 + PAGE_SIZE * index);
}

static volatile page_table* get_or_create_page_table(uintptr_t virt_addr) {
    size_t pd_idx = virt_addr >> 22;

    page_directory_entry* pde = current_page_directory()->entries + pd_idx;
    bool created = false;
    if (!pde->present) {
        pde->raw = page_alloc();
        if (IS_ERR(pde->raw))
            return ERR_CAST(pde->raw);

        pde->present = pde->write = pde->user = true;
        created = true;
    }

    volatile page_table* pt = get_page_table_from_index(pd_idx);
    if (created)
        memset((void*)pt, 0, sizeof(page_table));

    return pt;
}

static volatile page_table_entry* get_pte(uintptr_t virt_addr) {
    size_t pd_idx = virt_addr >> 22;
    page_directory_entry* pde = current_page_directory()->entries + pd_idx;
    if (!pde->present)
        return NULL;

    volatile page_table* pt = get_page_table_from_index(pd_idx);
    return pt->entries + ((virt_addr >> 12) & 0x3ff);
}

static volatile page_table_entry* get_or_create_pte(uintptr_t virt_addr) {
    volatile page_table* pt = get_or_create_page_table(virt_addr);
    if (IS_ERR(pt))
        return ERR_CAST(pt);
    return pt->entries + ((virt_addr >> 12) & 0x3ff);
}

uintptr_t virt_to_phys(void* virt_addr) {
    uintptr_t addr = (uintptr_t)virt_addr;
    const volatile page_table_entry* pte = get_pte(addr);
    ASSERT(pte);
    ASSERT(pte->present);
    return (pte->raw & ~PTE_FLAGS_MASK) | (addr & PTE_FLAGS_MASK);
}

struct page_directory* page_directory_create(void) {
    struct page_directory* dst = kmalloc(sizeof(struct page_directory));
    if (!dst)
        return ERR_PTR(-ENOMEM);

    // userland
    memset(dst->entries, 0, KERNEL_PDE_IDX * sizeof(page_directory_entry));

    // kernel
    memcpy(dst->entries + KERNEL_PDE_IDX,
           (void*)(kernel_page_directory->entries + KERNEL_PDE_IDX),
           (1023 - KERNEL_PDE_IDX) * sizeof(page_directory_entry));

    // recursive
    page_directory_entry* last_entry = dst->entries + 1023;
    last_entry->raw = virt_to_phys(dst);
    last_entry->present = last_entry->write = true;

    return dst;
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
                .ref_count = num_cpus - 1,
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
                ++msg->ref_count;
                cpu_unicast_message(cpu, msg);
            }
        }
    }

    // While other CPUs are flushing TLBs, we can flush this CPU's TLB
    for (uintptr_t addr = virt_addr; addr < virt_addr + size; addr += PAGE_SIZE)
        flush_tlb_single(addr);

    // Wait for other CPUs to finish flushing TLBs
    if (msg) {
        while (msg->ref_count)
            cpu_pause();
        cpu_free_message(msg);
    }

    pop_cli(int_flag);
}

// quickmap temporarily maps a physical page to the fixed virtual addresses,
// which are at the last two pages of the kernel page directory

#define QUICKMAP_PAGE 1022
#define QUICKMAP_PAGE_TABLE 1023

// this is locked in page_directory_clone_current
static struct mutex quickmap_lock;

static uintptr_t quickmap(size_t which, uintptr_t phys_addr, uint32_t flags) {
    volatile page_table* pt = get_page_table_from_index(KERNEL_PDE_IDX);
    volatile page_table_entry* pte = pt->entries + which;
    ASSERT(pte->raw == 0);
    pte->raw = phys_addr | flags;
    pte->present = true;
    uintptr_t virt_addr = KERNEL_VIRT_ADDR + PAGE_SIZE * which;
    flush_tlb_range(virt_addr, PAGE_SIZE);
    return virt_addr;
}

static void unquickmap(size_t which) {
    volatile page_table* pt = get_page_table_from_index(KERNEL_PDE_IDX);
    volatile page_table_entry* pte = pt->entries + which;
    ASSERT(pte->present);
    pte->raw = 0;
    flush_tlb_range(KERNEL_VIRT_ADDR + PAGE_SIZE * which, PAGE_SIZE);
}

static uintptr_t clone_page_table(const volatile page_table* src,
                                  uintptr_t src_virt_addr) {
    uintptr_t dest_pt_phys_addr = page_alloc();
    if (IS_ERR(dest_pt_phys_addr))
        return dest_pt_phys_addr;

    uintptr_t dest_pt_virt_addr =
        quickmap(QUICKMAP_PAGE_TABLE, dest_pt_phys_addr, PTE_WRITE);
    volatile page_table* dest_pt = (volatile page_table*)dest_pt_virt_addr;

    for (size_t i = 0; i < 1024; ++i) {
        if (!src->entries[i].present) {
            dest_pt->entries[i].raw = 0;
            continue;
        }

        if (src->entries[i].raw & PTE_SHARED) {
            dest_pt->entries[i].raw = src->entries[i].raw;
            page_ref(src->entries[i].raw & ~PTE_FLAGS_MASK);
            continue;
        }

        uintptr_t dest_page_phys_addr = page_alloc();
        if (IS_ERR(dest_page_phys_addr)) {
            unquickmap(QUICKMAP_PAGE_TABLE);
            return dest_page_phys_addr;
        }

        dest_pt->entries[i].raw =
            dest_page_phys_addr | (src->entries[i].raw & PTE_FLAGS_MASK);

        uintptr_t dest_page_virt_addr =
            quickmap(QUICKMAP_PAGE, dest_page_phys_addr, PTE_WRITE);
        memcpy((void*)dest_page_virt_addr,
               (void*)(src_virt_addr + PAGE_SIZE * i), PAGE_SIZE);
        unquickmap(QUICKMAP_PAGE);
    }

    unquickmap(QUICKMAP_PAGE_TABLE);
    return dest_pt_phys_addr;
}

struct page_directory* page_directory_clone_current(void) {
    struct page_directory* dst = page_directory_create();
    if (IS_ERR(dst))
        return dst;

    // copy userland region

    mutex_lock(&quickmap_lock);

    struct page_directory* src = current_page_directory();
    for (size_t i = 0; i < KERNEL_PDE_IDX; ++i) {
        if (!src->entries[i].present) {
            dst->entries[i].raw = 0;
            continue;
        }

        volatile page_table* pt = get_page_table_from_index(i);
        uintptr_t cloned_pt_phys_addr = clone_page_table(pt, i * 0x400000);
        if (IS_ERR(cloned_pt_phys_addr)) {
            mutex_unlock(&quickmap_lock);
            return ERR_PTR(cloned_pt_phys_addr);
        }

        dst->entries[i].raw =
            cloned_pt_phys_addr | (src->entries[i].raw & PTE_FLAGS_MASK);
    }

    mutex_unlock(&quickmap_lock);

    return dst;
}

extern unsigned char kernel_page_directory_start[];

struct page_directory* kernel_page_directory =
    (struct page_directory*)((uintptr_t)kernel_page_directory_start +
                             KERNEL_VIRT_ADDR);

void page_directory_destroy_current(void) {
    struct page_directory* pd = current_page_directory();
    ASSERT(pd != kernel_page_directory);

    for (size_t i = 0; i < KERNEL_PDE_IDX; ++i) {
        if (!pd->entries[i].present)
            continue;

        volatile page_table* pt = get_page_table_from_index(i);
        for (size_t j = 0; j < 1024; ++j) {
            if (pt->entries[j].present)
                page_unref(pt->entries[i].raw & ~PTE_FLAGS_MASK);
        }
    }

    ASSERT(current);
    // current->vm->page_directory has to be updated BEFORE switching page
    // directory. Otherwise, when we are preempted between the two operations,
    // current->vm->page_directory will be out of sync with the actual active
    // page directory.
    current->vm->page_directory = kernel_page_directory;
    page_directory_switch(kernel_page_directory);

    for (size_t i = 0; i < KERNEL_PDE_IDX; ++i) {
        if (pd->entries[i].present)
            page_unref(pd->entries[i].raw & ~PTE_FLAGS_MASK);
    }

    kfree(pd);
}

void page_directory_switch(struct page_directory* to) {
    uintptr_t phys_addr = virt_to_phys(to);
    write_cr3(phys_addr);
    ASSERT(phys_addr == virt_to_phys((void*)0xfffff000));
}

void page_table_init(void) {
    kprintf("page_table: kernel page directory is at P%#x\n",
            (uintptr_t)kernel_page_directory_start);

    // Populate page directory entries for kernel space so that all vm instances
    // share the same kernel space
    for (size_t virt_addr = KERNEL_HEAP_START; virt_addr < KERNEL_HEAP_END;
         virt_addr += 1024 * PAGE_SIZE)
        ASSERT_OK(get_or_create_page_table(virt_addr));
}

int page_table_map_anon(uintptr_t virt_addr, uintptr_t size, uint16_t flags) {
    ASSERT((virt_addr % PAGE_SIZE) == 0);
    ASSERT((size % PAGE_SIZE) == 0);

    int ret = 0;
    uintptr_t virt_cursor = virt_addr;
    uintptr_t virt_end = virt_addr + size;

    for (; virt_cursor < virt_end; virt_cursor += PAGE_SIZE) {
        volatile page_table_entry* pte = get_or_create_pte(virt_cursor);
        if (IS_ERR(pte)) {
            ret = PTR_ERR(pte);
            goto fail;
        }
        ASSERT(!pte->present);

        uintptr_t phys_addr = page_alloc();
        if (IS_ERR(phys_addr)) {
            ret = PTR_ERR(phys_addr);
            goto fail;
        }

        pte->raw = phys_addr | flags;
        pte->present = true;
    }

    flush_tlb_range(virt_addr, size);

    return 0;

fail:
    page_table_unmap(virt_addr, virt_cursor - virt_addr);
    return ret;
}

int page_table_map_phys(uintptr_t virt_addr, uintptr_t phys_addr,
                        uintptr_t size, uint16_t flags) {
    ASSERT((virt_addr % PAGE_SIZE) == 0);
    ASSERT((phys_addr % PAGE_SIZE) == 0);
    ASSERT((size % PAGE_SIZE) == 0);

    int ret = 0;
    uintptr_t virt_cursor = virt_addr;
    uintptr_t virt_end = virt_addr + size;
    uintptr_t phys_cursor = phys_addr;

    for (; virt_cursor < virt_end;
         virt_cursor += PAGE_SIZE, phys_cursor += PAGE_SIZE) {
        volatile page_table_entry* pte = get_or_create_pte(virt_cursor);
        if (IS_ERR(pte)) {
            ret = PTR_ERR(pte);
            goto fail;
        }
        ASSERT(!pte->present);

        page_ref(phys_cursor);

        pte->raw = phys_cursor | flags;
        pte->present = true;
    }

    flush_tlb_range(virt_addr, size);
    return 0;

fail:
    page_table_unmap(virt_addr, virt_cursor - virt_addr);
    return ret;
}

int page_table_shallow_copy(uintptr_t to_virt_addr, uintptr_t from_virt_addr,
                            uintptr_t size, uint16_t new_flags) {
    ASSERT((to_virt_addr % PAGE_SIZE) == 0);
    ASSERT((from_virt_addr % PAGE_SIZE) == 0);
    ASSERT((size % PAGE_SIZE) == 0);

    int ret = 0;
    uintptr_t from_virt_cursor = from_virt_addr;
    uintptr_t from_virt_end = from_virt_addr + size;
    uintptr_t to_virt_cursor = to_virt_addr;

    for (; from_virt_cursor < from_virt_end;
         from_virt_cursor += PAGE_SIZE, to_virt_cursor += PAGE_SIZE) {
        volatile page_table_entry* from_pte = get_pte(from_virt_cursor);
        ASSERT(from_pte && from_pte->present);

        volatile page_table_entry* to_pte = get_or_create_pte(to_virt_cursor);
        if (IS_ERR(to_pte)) {
            ret = PTR_ERR(to_pte);
            goto fail;
        }
        ASSERT(!to_pte->present);

        uintptr_t phys_addr = from_pte->raw & ~PTE_FLAGS_MASK;
        page_ref(phys_addr);

        to_pte->raw = phys_addr | new_flags;
        to_pte->present = true;
    }

    flush_tlb_range(to_virt_addr, size);
    return 0;

fail:
    page_table_unmap(to_virt_addr, to_virt_cursor - to_virt_addr);
    return ret;
}

void page_table_unmap(uintptr_t virt_addr, uintptr_t size) {
    ASSERT((virt_addr % PAGE_SIZE) == 0);
    ASSERT((size % PAGE_SIZE) == 0);

    uintptr_t virt_end = virt_addr + ROUND_UP(size, PAGE_SIZE);
    for (uintptr_t virt_cursor = virt_addr; virt_cursor < virt_end;
         virt_cursor += PAGE_SIZE) {
        volatile page_table_entry* pte = get_pte(virt_cursor);
        ASSERT(pte && pte->present);
        page_unref(pte->raw & ~PTE_FLAGS_MASK);
        pte->raw = 0;
    }
    flush_tlb_range(virt_addr, size);
}

void page_table_set_flags(uintptr_t virt_addr, uintptr_t size, uint16_t flags) {
    ASSERT((virt_addr % PAGE_SIZE) == 0);
    ASSERT((size % PAGE_SIZE) == 0);

    uintptr_t virt_end = virt_addr + ROUND_UP(size, PAGE_SIZE);
    for (uintptr_t virt_cursor = virt_addr; virt_cursor < virt_end;
         virt_cursor += PAGE_SIZE) {
        volatile page_table_entry* pte = get_pte(virt_cursor);
        ASSERT(pte && pte->present);
        pte->raw = (pte->raw & ~PTE_FLAGS_MASK) | flags;
        pte->present = true;
    }
    flush_tlb_range(virt_addr, size);
}
