#include "asm_wrapper.h"
#include "interrupts.h"
#include "process.h"
#include "system.h"

#define TIMER0_CTL 0x40
#define TIMER0_SELECT 0x00
#define WRITE_WORD 0x30
#define MODE_SQUARE_WAVE 0x06
#define BASE_FREQUENCY 1193182

static void pit_handler(registers* regs) {
    (void)regs;
    KASSERT(!interrupts_enabled());
    process_switch();
}

void pit_init(uint32_t freq) {
    uint16_t div;
    if (freq < 19) {
        div = 0xffff;
    } else if (freq > BASE_FREQUENCY) {
        div = 1;
    } else {
        div = BASE_FREQUENCY / freq;
    }
    out8(TIMER0_CTL, TIMER0_SELECT | WRITE_WORD | MODE_SQUARE_WAVE);
    out8(TIMER0_CTL, div & 0xff);
    out8(TIMER0_CTL, div >> 8);
    idt_register_interrupt_handler(IRQ0, pit_handler);
}
