#include <kernel/arch/io.h>
#include <kernel/arch/x86/interrupts/interrupts.h>
#include <kernel/interrupts.h>

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
    out8(PIC1_DATA, IRQ(0));
    out8(PIC2_DATA, IRQ(NUM_IRQS_PER_PIC));
    out8(PIC1_DATA, 4);
    out8(PIC2_DATA, 2);
    out8(PIC1_DATA, ICW4_8086);
    out8(PIC2_DATA, ICW4_8086);
    out8(PIC1_DATA, 0);
    out8(PIC2_DATA, 0);
}

void i8259_init(void) { remap_pic(); }

void i8259_disable(void) {
    out8(PIC1_DATA, 0xff);
    out8(PIC2_DATA, 0xff);
}

void i8259_eoi(uint8_t irq) {
    ASSERT(irq < NUM_IRQS);
    if (irq >= NUM_IRQS_PER_PIC)
        out8(PIC2_CMD, PIC_EOI);
    out8(PIC1_CMD, PIC_EOI);
}
