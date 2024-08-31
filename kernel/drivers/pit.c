#include <kernel/interrupts/interrupts.h>
#include <kernel/sched.h>
#include <kernel/system.h>
#include <kernel/time.h>

#define TIMER0_CTL 0x40
#define PIT_CTL 0x43
#define TIMER0_SELECT 0x00
#define WRITE_WORD 0x30
#define MODE_SQUARE_WAVE 0x06
#define BASE_FREQUENCY 1193182

static void tick(struct registers* regs) {
    time_tick();

    // When SMP is active, the sched_tick is called from the per-CPU
    // local APIC timer interrupt handler.
    if (!smp_active)
        sched_tick(regs);
}

void pit_init(void) {
    uint16_t div = BASE_FREQUENCY / CLK_TCK;
    out8(PIT_CTL, TIMER0_SELECT | WRITE_WORD | MODE_SQUARE_WAVE);
    out8(TIMER0_CTL, div & 0xff);
    out8(TIMER0_CTL, div >> 8);
    idt_set_interrupt_handler(IRQ(0), tick);
}
