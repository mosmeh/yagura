#include "pit.h"
#include <kernel/interrupts.h>
#include <kernel/panic.h>
#include <kernel/scheduler.h>
#include <kernel/system.h>
#include <kernel/time.h>

#define TIMER0_CTL 0x40
#define PIT_CTL 0x43
#define TIMER0_SELECT 0x00
#define WRITE_WORD 0x30
#define MODE_SQUARE_WAVE 0x06
#define BASE_FREQUENCY 1193182

static void (*tick_handler)(void);

static void irq_handler(registers* regs) {
    (void)regs;
    ASSERT(!interrupts_enabled());

    if (tick_handler)
        tick_handler();

    bool in_kernel = (regs->cs & 3) == 0;
    scheduler_tick(in_kernel);
}

void pit_init(void) {
    uint16_t div = BASE_FREQUENCY / CLK_TCK;
    out8(PIT_CTL, TIMER0_SELECT | WRITE_WORD | MODE_SQUARE_WAVE);
    out8(TIMER0_CTL, div & 0xff);
    out8(TIMER0_CTL, div >> 8);
    idt_set_interrupt_handler(IRQ(0), irq_handler);
}

void pit_set_tick_handler(void (*handler)(void)) { tick_handler = handler; }
