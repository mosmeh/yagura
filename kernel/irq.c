#include "asm_wrapper.h"
#include "system.h"
#include <common/extra.h>

#define PIC1_CMD 0x20
#define PIC1_DATA 0x21
#define PIC2_CMD 0xa0
#define PIC2_DATA 0xa1

#define PIC_EOI 0x20

#define ICW1_ICW4 0x01
#define ICW1_INIT 0x10
#define ICW4_8086 0x01

#define NUM_IRQS_PER_PIC 8

static void remap_pic(void) {
    out8(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
    out8(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
    out8(PIC1_DATA, IRQ0);
    out8(PIC2_DATA, IRQ0 + NUM_IRQS_PER_PIC);
    out8(PIC1_DATA, 4);
    out8(PIC2_DATA, 2);
    out8(PIC1_DATA, ICW4_8086);
    out8(PIC2_DATA, ICW4_8086);
    out8(PIC1_DATA, 0);
    out8(PIC2_DATA, 0);
}

#define DEFINE_IRQ(num)                                                        \
    void irq##num(void);                                                       \
    __asm__("irq" #num ":\n"                                                   \
            "cli\n"                                                            \
            "pushl $0\n"                                                       \
            "pushl $" STRINGIFY(IRQ0 + num) "\n"                               \
                                            "jmp irq_common_stub");

DEFINE_IRQ(0)
DEFINE_IRQ(1)
DEFINE_IRQ(2)
DEFINE_IRQ(3)
DEFINE_IRQ(4)
DEFINE_IRQ(5)
DEFINE_IRQ(6)
DEFINE_IRQ(7)
DEFINE_IRQ(8)
DEFINE_IRQ(9)
DEFINE_IRQ(10)
DEFINE_IRQ(11)
DEFINE_IRQ(12)
DEFINE_IRQ(13)
DEFINE_IRQ(14)
DEFINE_IRQ(15)

extern interrupt_handler_fn interrupt_handlers[256];

void irq_handler(registers* regs) {
    if (regs->num >= NUM_IRQS_PER_PIC)
        out8(PIC2_CMD, PIC_EOI);

    out8(PIC1_CMD, PIC_EOI);

    interrupt_handler_fn handler = interrupt_handlers[regs->num];
    if (handler)
        handler(regs);
}

void irq_init(void) {
    remap_pic();

#define REGISTER_IRQ(num) idt_set_gate(IRQ0 + num, (uint32_t)irq##num, 8, 0x8e)

    REGISTER_IRQ(0);
    REGISTER_IRQ(1);
    REGISTER_IRQ(2);
    REGISTER_IRQ(3);
    REGISTER_IRQ(4);
    REGISTER_IRQ(5);
    REGISTER_IRQ(6);
    REGISTER_IRQ(7);
    REGISTER_IRQ(8);
    REGISTER_IRQ(9);
    REGISTER_IRQ(10);
    REGISTER_IRQ(11);
    REGISTER_IRQ(12);
    REGISTER_IRQ(13);
    REGISTER_IRQ(14);
    REGISTER_IRQ(15);

    idt_flush();
}
