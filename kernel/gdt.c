#include <kernel/cpu.h>
#include <kernel/gdt.h>
#include <kernel/interrupts/interrupts.h>

static void gdt_set_segment(struct gdt_segment* gdt, size_t index, uint32_t low,
                            uint32_t high) {
    gdt[index] = (struct gdt_segment){
        .low = low,
        .high = high,
    };
}

static void gdt_set_base_limit(struct gdt_segment* gdt, size_t index,
                               uint32_t base, uint32_t limit) {
    struct gdt_segment* segment = gdt + index;
    segment->base_lo = base & 0xffff;
    segment->base_hi = (base >> 16) & 0xff;
    segment->base_hi2 = (base >> 24) & 0xff;
    segment->limit_lo = limit & 0xffff;
    segment->limit_hi = (limit >> 16) & 0xf;
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

    gdt_set_segment(gdt, 0, 0, 0);
    gdt_set_segment(gdt, GDT_ENTRY_KERNEL_CS, 0x0000ffff, 0x00af9a00);
    gdt_set_segment(gdt, GDT_ENTRY_KERNEL_DS, 0x0000ffff, 0x00af9200);
    gdt_set_segment(gdt, GDT_ENTRY_USER_DS, 0x0000ffff, 0x008ff200);
    gdt_set_segment(gdt, GDT_ENTRY_USER_CS, 0x0000ffff, 0x00affa00);

    gdt[GDT_ENTRY_TSS] = (struct gdt_segment){
        .dpl = 0,
        .segment_present = 1,
        .granularity = 0,
        .operation_size64 = 0,
        .operation_size32 = 1,
        .descriptor_type = 0,
        .type = 0x9, // TSS
    };
    gdt_set_base_limit(gdt, GDT_ENTRY_TSS, (uintptr_t)tss & 0xffffffff,
                       sizeof(cpu->tss) - 1);
    gdt_set_segment(gdt, GDT_ENTRY_TSS2, (uint64_t)tss >> 32, 0);

    for (size_t i = 0; i < NUM_GDT_TLS_ENTRIES; ++i)
        gdt_set_segment(gdt, GDT_ENTRY_TLS_MIN + i, 0, 0);

    gdt[GDT_ENTRY_CPU_ID] = (struct gdt_segment){
        .dpl = 0,
        .segment_present = 1,
        .granularity = 0,
        .operation_size64 = 0,
        .operation_size32 = 1,
        .descriptor_type = 1,
        .type = 0x5, // Read-only grows-down data
    };
    gdt_set_base_limit(gdt, GDT_ENTRY_CPU_ID, 0, cpu_id);

    *tss = (struct tss){
        .iomapbase = sizeof(struct tss),
    };

    __asm__ volatile("lgdt %0" : : "m"(*gdtr) : "memory");
    __asm__ volatile("ltr %0" : : "r"(TSS_SELECTOR));
}

void gdt_set_cpu_kernel_stack(uintptr_t stack_top) {
    ASSERT(!interrupts_enabled());
    ASSERT(stack_top);
    struct tss* tss = &cpu_get_current()->tss;
    tss->rsp0l = stack_top & 0xffffffff;
    tss->rsp0h = stack_top >> 32;
}
