#include <kernel/arch/x86/gdt.h>
#include <kernel/arch/x86/interrupts/interrupts.h>
#include <kernel/cpu.h>

static void set_segment(struct gdt_segment* gdt, size_t index, uint32_t low,
                        uint32_t high) {
    gdt[index] = (struct gdt_segment){
        .low = low,
        .high = high,
    };
}

static void set_base_limit(struct gdt_segment* gdt, size_t index, uint32_t base,
                           uint32_t limit) {
    struct gdt_segment* segment = gdt + index;
    segment->base_lo = base & 0xffff;
    segment->base_mid = (base >> 16) & 0xff;
    segment->base_hi = (base >> 24) & 0xff;
    segment->limit_lo = limit & 0xffff;
    segment->limit_hi = (limit >> 16) & 0xf;
}

void gdt_init_cpu(void) {
    // Avoid using cpu_get_current() here, as it relies on GDT_ENTRY_CPU_ID
    struct cpu* cpu = NULL;
    size_t cpu_id = 0;
    uint8_t apic_id = lapic_get_id();
    for (; cpu_id < num_cpus; ++cpu_id) {
        if (cpus[cpu_id]->arch.apic_id == apic_id) {
            cpu = cpus[cpu_id];
            break;
        }
    }
    ASSERT(cpu);

    struct gdtr* gdtr = &cpu->arch.gdtr;
    struct gdt_segment* gdt = cpu->arch.gdt;
    struct tss* tss = &cpu->arch.tss;

    *gdtr = (struct gdtr){
        .limit = sizeof(cpu->arch.gdt) - 1,
        .base = (uintptr_t)gdt,
    };

    set_segment(gdt, 0, 0, 0);

#ifdef ARCH_I386
    set_segment(gdt, GDT_ENTRY_KERNEL_CS, 0x0000ffff, 0x00cf9a00);
    set_segment(gdt, GDT_ENTRY_KERNEL_DS, 0x0000ffff, 0x00cf9200);
    set_segment(gdt, GDT_ENTRY_USER_CS, 0x0000ffff, 0x00cffa00);
    set_segment(gdt, GDT_ENTRY_USER_DS, 0x0000ffff, 0x00cff200);
#endif
#ifdef ARCH_X86_64
    set_segment(gdt, GDT_ENTRY_KERNEL_CS, 0x0000ffff, 0x00af9a00);
    set_segment(gdt, GDT_ENTRY_KERNEL_DS, 0x0000ffff, 0x008f9200);
    set_segment(gdt, GDT_ENTRY_USER_DS, 0x0000ffff, 0x008ff200);
    set_segment(gdt, GDT_ENTRY_USER_CS, 0x0000ffff, 0x00affa00);
#endif

    gdt[GDT_ENTRY_TSS] = (struct gdt_segment){
        .dpl = 0,
        .segment_present = 1,
        .granularity = 0,
        .operation_size64 = 0,
        .operation_size32 = 1,
        .descriptor_type = 0,
        .type = 0x9, // TSS
    };
    set_base_limit(gdt, GDT_ENTRY_TSS, (uintptr_t)tss & 0xffffffff,
                   sizeof(*tss) - 1);
#ifdef ARCH_X86_64
    set_segment(gdt, GDT_ENTRY_TSS2, (uintptr_t)tss >> 32, 0);
#endif

    for (size_t i = 0; i < NUM_GDT_TLS_ENTRIES; ++i)
        set_segment(gdt, GDT_ENTRY_TLS_MIN + i, 0, 0);

    gdt[GDT_ENTRY_CPU_ID] = (struct gdt_segment){
        .dpl = 0,
        .segment_present = 1,
        .granularity = 0,
        .operation_size64 = 0,
        .operation_size32 = 1,
        .descriptor_type = 1,
        .type = 0x5, // Read-only grows-down data
    };
    set_base_limit(gdt, GDT_ENTRY_CPU_ID, 0, cpu_id);

    *tss = (struct tss){
#ifdef ARCH_I386
        .ss0 = KERNEL_DS,
#endif
        .iomap_base = sizeof(struct tss),
    };

    __asm__ volatile("lgdt %[gdtr]\n"
                     "movw %%ax, %%ds\n"
                     "movw %%ax, %%es\n"
                     "movw %%ax, %%fs\n"
                     "movw %%ax, %%gs\n"
                     "movw %%ax, %%ss\n"
                     :
                     : [gdtr] "m"(*gdtr), "a"(KERNEL_DS)
                     : "memory");

#ifdef ARCH_I386
    __asm__ volatile("ljmpl %[kernel_cs], $1f\n"
                     "1:\n"
                     :
                     : [kernel_cs] "i"(KERNEL_CS)
                     : "memory");
#endif

    __asm__ volatile("ltr %%ax" : : "a"(TSS_SELECTOR) : "memory");
}
