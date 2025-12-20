#include <kernel/acpi.h>
#include <kernel/cpu.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/memory/vm.h>
#include <kernel/sched.h>
#include <kernel/time.h>

#define LAPIC_ID 0x0020      // ID
#define LAPIC_VER 0x0030     // Version
#define LAPIC_TPR 0x0080     // Task Priority
#define LAPIC_EOI 0x00b0     // EOI
#define LAPIC_LDR 0x00d0     // Logical Destination
#define LAPIC_DFR 0x00e0     // Destination Format
#define LAPIC_SVR 0x00f0     // Spurious Interrupt Vector
#define LAPIC_ESR 0x0280     // Error Status
#define LAPIC_ICRLO 0x0300   // Interrupt Command
#define LAPIC_ICRHI 0x0310   // Interrupt Command [63:32]
#define LAPIC_TIMER 0x0320   // Local Vector Table 0 (TIMER)
#define LAPIC_THERMAL 0x0330 // Thermal Monitor LVT
#define LAPIC_PCINT 0x0340   // Performance Counter LVT
#define LAPIC_LINT0 0x0350   // Local Vector Table 1 (LINT0)
#define LAPIC_LINT1 0x0360   // Local Vector Table 2 (LINT1)
#define LAPIC_ERROR 0x0370   // Local Vector Table 3 (ERROR)
#define LAPIC_TICR 0x0380    // Timer Initial Count
#define LAPIC_TCCR 0x0390    // Timer Current Count
#define LAPIC_TDCR 0x03e0    // Timer Divide Configuration

#define LAPIC_SVR_ENABLE 0x00000100 // Unit Enable

#define LAPIC_TIMER_X1 0x0000000b       // divide counts by 1
#define LAPIC_TIMER_PERIODIC 0x00020000 // Periodic

#define LAPIC_LVT_MASKED 0x00010000 // Interrupt masked
#define LAPIC_LVT_TRIGGER_LEVEL 0x00004000

static volatile void* lapic;

void lapic_init(void) {
    const struct acpi* acpi = acpi_get();
    ASSERT(acpi);
    ASSERT(acpi->lapic_addr);

    unsigned char* addr =
        phys_map(acpi->lapic_addr, PAGE_SIZE, VM_READ | VM_WRITE);
    ASSERT_PTR(addr);
    ASSERT_OK(vm_populate(addr, addr + PAGE_SIZE, true));
    lapic = addr;

    idt_set_interrupt_handler(LAPIC_TIMER_VECTOR, sched_tick);
}

static uint32_t lapic_read(uint32_t reg) {
    ASSERT(lapic);
    return *(volatile uint32_t*)((uintptr_t)lapic + reg);
}

static void lapic_write(uint32_t reg, uint32_t value) {
    ASSERT(lapic);
    *(volatile uint32_t*)((uintptr_t)lapic + reg) = value;
}

#define CALIBRATION_TICKS 10

void lapic_init_cpu(void) {
    bool int_flag = push_cli();

    // Set logical APIC ID to be the same as the local APIC ID
    lapic_write(LAPIC_LDR, lapic_get_id() << 24);
    lapic_write(LAPIC_DFR, 0xffffffff);

    lapic_write(LAPIC_ERROR, LAPIC_ERROR_VECTOR);
    lapic_write(LAPIC_SVR, LAPIC_SVR_ENABLE | SPURIOUS_VECTOR);

    lapic_write(LAPIC_THERMAL, LAPIC_LVT_MASKED);
    lapic_write(LAPIC_PCINT, LAPIC_LVT_MASKED);
    lapic_write(LAPIC_LINT0, LAPIC_LVT_MASKED);
    lapic_write(LAPIC_LINT1, LAPIC_LVT_MASKED);

    lapic_write(LAPIC_TPR, 0);

    // Set up and calibrate the local APIC timer so that it ticks at the same
    // rate as uptime.

    lapic_write(LAPIC_TIMER, LAPIC_TIMER_PERIODIC | LAPIC_TIMER_VECTOR);
    lapic_write(LAPIC_TDCR, LAPIC_TIMER_X1);

    // Set ICR to a large value so that we can read TCCR before the timer ticks.
    lapic_write(LAPIC_TICR, UINT32_MAX);

    sti();
    uint32_t start_uptime = uptime;
    while (uptime <= start_uptime)
        pause();
    // uptime = start_uptime + 1
    uint32_t start_tccr = lapic_read(LAPIC_TCCR);
    while (uptime <= start_uptime + CALIBRATION_TICKS)
        pause();
    cli();
    // uptime = start_uptime + CALIBRATION_TICKS + 1
    uint32_t end_tccr = lapic_read(LAPIC_TCCR);

    ASSERT(start_tccr >= end_tccr);
    uint32_t period = (start_tccr - end_tccr) / CALIBRATION_TICKS;
    lapic_write(LAPIC_TICR, MAX(1, period));

    pop_cli(int_flag);
}

uint8_t lapic_get_id(void) { return lapic ? (lapic_read(LAPIC_ID) >> 24) : 0; }

void lapic_eoi(void) {
    if (lapic)
        lapic_write(LAPIC_EOI, 0);
}

static void wait_for_pending_ipi(void) {
    while (lapic_read(LAPIC_ICRLO) & LAPIC_ICRLO_DELIVS)
        cpu_pause();
}

void lapic_write_icr(uint32_t hi, uint32_t lo) {
    wait_for_pending_ipi();
    lapic_write(LAPIC_ICRHI, hi);
    lapic_write(LAPIC_ICRLO, lo);
    wait_for_pending_ipi();
}

void lapic_broadcast_ipi(void) {
    lapic_write_icr(0xff << 24, LAPIC_ICRLO_ASSERT | LAPIC_ICRLO_LOGICAL |
                                    LAPIC_ICRLO_ALL_EXCL_SELF | IPI_VECTOR);
}

void lapic_unicast_ipi(uint8_t apic_id) {
    lapic_write_icr(apic_id << 24,
                    LAPIC_ICRLO_ASSERT | LAPIC_ICRLO_LOGICAL | IPI_VECTOR);
}

#define IO_APIC_REG_ID 0x00            // Register index: ID
#define IO_APIC_REG_VER 0x01           // Register index: version
#define IO_APIC_REDIRECTION_TABLE 0x10 // Redirection table base

#define IO_APIC_INT_DISABLED 0x00010000  // Interrupt disabled
#define IO_APIC_INT_LEVEL 0x00008000     // Level-triggered (vs edge-)
#define IO_APIC_INT_ACTIVELOW 0x00002000 // Active low (vs high)
#define IO_APIC_INT_LOGICAL 0x00000800   // Destination is CPU id (vs APIC ID)

static void io_apic_write(volatile void* io_apic, uint32_t reg,
                          uint32_t value) {
    *(volatile uint32_t*)io_apic = reg;
    *(volatile uint32_t*)((unsigned char*)io_apic + 0x10) = value;
}

static uint32_t io_apic_read(volatile void* io_apic, uint32_t reg) {
    *(volatile uint32_t*)io_apic = reg;
    return *(volatile uint32_t*)((unsigned char*)io_apic + 0x10);
}

static void io_apic_write_redirection(volatile void* io_apic, uint8_t index,
                                      uint8_t dest, uint32_t value) {
    io_apic_write(io_apic, IO_APIC_REDIRECTION_TABLE + 2 * index, value);
    io_apic_write(io_apic, IO_APIC_REDIRECTION_TABLE + 2 * index + 1,
                  (uint32_t)dest << 24);
}

void io_apic_init(void) {
    const struct acpi* acpi = acpi_get();
    ASSERT(acpi);

    // Route all interrupts to the BSP.
    uint8_t apic_id = cpu_get_bsp()->apic_id;

    for (const struct io_apic** p = acpi->io_apics; *p; ++p) {
        volatile void* io_apic = kmap((*p)->io_apic_addr);
        ASSERT_PTR(io_apic);

        size_t num_redirections =
            ((io_apic_read(io_apic, IO_APIC_REG_VER) >> 16) & 0xff) + 1;

        // First, mask all interrupts.
        for (size_t i = 0; i < num_redirections; ++i)
            io_apic_write_redirection(io_apic, i, 0, IO_APIC_INT_DISABLED);

        uint32_t gsi_base = (*p)->global_system_interrupt_base;

        // Then, route 0..NUM_IRQS to IRQ(0)..IRQ(NUM_IRQS) if this I/O APIC is
        // responsible for them.
        for (size_t i = 0; i < num_redirections && i + gsi_base < NUM_IRQS; ++i)
            io_apic_write_redirection(io_apic, i, apic_id, IRQ(i + gsi_base));

        // There may be interrupt source overrides that route interrupts to
        // global system interrupts different from the source IRQ numbers.
        // For example, the timer interrupt (IRQ0 on 8259 PIC) is
        // usually routed to IRQ2 on I/O APIC.
        // We invert the redirections here so that it ends up in the identity
        // mapping.
        for (const struct interrupt_source_override** iso =
                 acpi->interrupt_source_overrides;
             *iso; ++iso) {
            uint32_t gsi = (*iso)->global_system_interrupt;
            if (gsi < gsi_base || gsi_base + num_redirections <= gsi)
                continue;
            if ((*iso)->source >= NUM_IRQS)
                continue;
            uint32_t value = IRQ((*iso)->source);
            if (((*iso)->flags & 3) == 3)
                value |= IO_APIC_INT_ACTIVELOW;
            if ((((*iso)->flags >> 2) & 3) == 3)
                value |= IO_APIC_INT_LEVEL;
            io_apic_write_redirection(io_apic, gsi - gsi_base, apic_id, value);
        }

        kunmap((void*)io_apic);
    }
}
