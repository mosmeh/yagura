#include <kernel/arch/io.h>
#include <kernel/interrupts.h>
#include <kernel/task/sched.h>
#include <kernel/time.h>

#define TIMER0_CTL 0x40
#define PIT_CTL 0x43
#define TIMER0_SELECT 0x00
#define WRITE_WORD 0x30
#define MODE_RATE_GENERATOR 0x04
#define BASE_FREQUENCY 1193182

STATIC_ASSERT(CLK_TCK <= BASE_FREQUENCY);

static void tick(struct registers* regs) {
    time_tick();
    sched_tick(regs);
}

void pit_init(void) {
    uint16_t div = BASE_FREQUENCY / CLK_TCK;
    out8(PIT_CTL, TIMER0_SELECT | WRITE_WORD | MODE_RATE_GENERATOR);
    out8(TIMER0_CTL, div & 0xff);
    out8(TIMER0_CTL, div >> 8);
    arch_interrupts_set_handler(IRQ(0), tick);
}
