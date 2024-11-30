#include "acpi.h"
#include "cpu.h"
#include "interrupts/interrupts.h"
#include "kmsg.h"
#include "memory/memory.h"
#include "panic.h"
#include "sched.h"
#include "system.h"
#include <common/string.h>

static bool can_enable_smp(void) {
    if (cmdline_contains("nosmp")) {
        kprint("smp: SMP disabled by kernel command line\n");
        return false;
    }
    if (!cpu_has_feature(cpu_get_bsp(), X86_FEATURE_APIC)) {
        kprint("smp: APIC not supported\n");
        return false;
    }
    const struct acpi* acpi = acpi_get();
    if (!acpi) {
        kprint("smp: failed to get ACPI tables\n");
        return false;
    }
    size_t num_enabled_cpus = 0;
    for (const struct local_apic** p = acpi->local_apics; *p; ++p) {
        if ((*p)->flags & ACPI_LOCAL_APIC_ENABLED)
            ++num_enabled_cpus;
    }
    if (num_enabled_cpus <= 1) {
        kprint("smp: only one CPU detected\n");
        return false;
    }
    if (!acpi->lapic_addr) {
        kprint("smp: no local APIC detected\n");
        return false;
    }
    if (!acpi->io_apics) {
        kprint("smp: no I/O APIC detected\n");
        return false;
    }
    return true;
}

extern unsigned char ap_trampoline_start[];
extern unsigned char ap_trampoline_end[];
static bool smp_enabled;
static atomic_uint num_ready_cpus = 1;
void* ap_stack_top;
atomic_bool smp_active;

void smp_init(void) {
    if (!can_enable_smp())
        return;

    cpu_init_smp();
    i8259_disable();
    io_apic_init();
    lapic_init();
    lapic_init_cpu();

    smp_enabled = true;
}

void smp_start(void) {
    if (!smp_enabled)
        return;

    ASSERT((uintptr_t)ap_trampoline_start % PAGE_SIZE == 0);
    size_t trampoline_size = ap_trampoline_end - ap_trampoline_start;
    for (size_t offset = 0; offset < trampoline_size; offset += PAGE_SIZE) {
        void* kaddr = kmap(AP_TRAMPOLINE_ADDR + offset);
        memcpy(kaddr, ap_trampoline_start + offset, PAGE_SIZE);
        kunmap(kaddr);
    }

    const struct acpi* acpi = acpi_get();
    ASSERT(acpi);

    size_t ap_stack_size = STACK_SIZE * (num_cpus - 1);
    unsigned char* ap_stack = kmalloc(ap_stack_size);
    ASSERT(ap_stack);
    ap_stack_top = ap_stack + ap_stack_size;

    STATIC_ASSERT(AP_TRAMPOLINE_ADDR < 0x100000);
    STATIC_ASSERT(AP_TRAMPOLINE_ADDR % 0x1000 == 0);

    // APs start in real mode (no paging), so they need identity mapping of
    // the initialization code.
    size_t init_npages = DIV_CEIL((uintptr_t)init_end, PAGE_SIZE);
    ASSERT_OK(page_table_map(0, 0, init_npages, PTE_WRITE));

    kprintf("smp: starting %u APs\n", num_cpus - 1);
    for (size_t i = 0; i < num_cpus; ++i) {
        struct cpu* cpu = cpus[i];
        if (cpu == cpu_get_bsp())
            continue;

        uint32_t dest = (uint32_t)cpu->apic_id << 24;

        // INIT IPI
        lapic_write_icr(dest, LAPIC_ICRLO_INIT | LAPIC_ICRLO_ASSERT);
        delay(10000);

        // Start Up IPI
        for (int j = 0; j < 2; ++j) {
            lapic_write_icr(dest, LAPIC_ICRLO_STARTUP | LAPIC_ICRLO_ASSERT |
                                      (AP_TRAMPOLINE_ADDR >> 12));
            delay(200);
        }
    }

    while (num_ready_cpus < num_cpus)
        pause();
    ASSERT(num_ready_cpus == num_cpus);

    // Remove the identity mapping
    page_table_unmap(0, init_npages);

    smp_active = true;
    kprint("smp: all APs started\n");
}

noreturn void ap_start(void) {
    gdt_init_cpu();
    cpu_init();
    idt_flush();
    lapic_init_cpu();

    ++num_ready_cpus;
    while (!smp_active)
        pause();
    flush_tlb();

    sched_start();
}
