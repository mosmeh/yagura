#include <kernel/cpu.h>
#include <kernel/gdt.h>
#include <kernel/interrupts/interrupts.h>

static void gdt_set_segment(struct gdt_segment* gdt, size_t index,
                            uint32_t base, uint32_t limit, uint8_t access,
                            uint8_t flags) {
    ASSERT(index < NUM_GDT_ENTRIES);
    struct gdt_segment* s = gdt + index;
    s->base_lo = base & 0xffff;
    s->base_mid = (base >> 16) & 0xff;
    s->base_hi = (base >> 24) & 0xff;

    s->limit_lo = limit & 0xffff;
    s->limit_hi = (limit >> 16) & 0xf;

    s->access = access;
    s->flags = flags & 0xf;
}

void gdt_init_cpu(void) {
    // Avoid using cpu_get_current() here, as it relies on GDT_ENTRY_CPU_ID
    struct cpu* cpu = NULL;
    size_t cpu_id = 0;
    uint8_t apic_id = lapic_get_id();
    for (; cpu_id < num_cpus; ++cpu_id) {
        if (cpus[cpu_id]->apic_id == apic_id) {
            cpu = cpus[cpu_id];
            break;
        }
    }
    ASSERT(cpu);

    struct gdtr* gdtr = &cpu->gdtr;
    struct gdt_segment* gdt = cpu->gdt;
    struct tss* tss = &cpu->tss;

    *gdtr = (struct gdtr){
        .limit = sizeof(cpu->gdt) - 1,
        .base = (uintptr_t)gdt,
    };

    gdt_set_segment(gdt, 0, 0, 0, 0, 0);
    gdt_set_segment(gdt, GDT_ENTRY_KERNEL_CS, 0, 0xfffff, 0x9a, 0xc);
    gdt_set_segment(gdt, GDT_ENTRY_KERNEL_DS, 0, 0xfffff, 0x92, 0xc);
    gdt_set_segment(gdt, GDT_ENTRY_USER_CS, 0, 0xfffff, 0xfa, 0xc);
    gdt_set_segment(gdt, GDT_ENTRY_USER_DS, 0, 0xfffff, 0xf2, 0xc);
    gdt_set_segment(gdt, GDT_ENTRY_TSS, (uint32_t)tss, sizeof(struct tss) - 1,
                    0x89, 0);

    for (size_t i = 0; i < NUM_GDT_TLS_ENTRIES; ++i)
        gdt_set_segment(gdt, GDT_ENTRY_TLS_MIN + i, 0, 0, 0, 0);

    gdt_set_segment(gdt, GDT_ENTRY_CPU_ID, 0, cpu_id, 0x95, 0x4);

    *tss = (struct tss){
        .ss0 = KERNEL_DS,
        .iomap_base = sizeof(struct tss),
    };

    __asm__ volatile("lgdt %0\n"
                     "movw %%ax, %%ds\n"
                     "movw %%ax, %%es\n"
                     "movw %%ax, %%fs\n"
                     "movw %%ax, %%gs\n"
                     "movw %%ax, %%ss\n"
                     "ljmpl $0x8, $1f\n"
                     "1:"
                     :
                     : "m"(*gdtr), "a"(KERNEL_DS)
                     : "memory");

    __asm__ volatile("ltr %%ax" ::"a"(TSS_SELECTOR));
}

void gdt_set_cpu_kernel_stack(uintptr_t stack_top) {
    ASSERT(!interrupts_enabled());
    ASSERT(stack_top);
    cpu_get_current()->tss.esp0 = stack_top;
}
