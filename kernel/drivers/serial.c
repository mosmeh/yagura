#include "serial.h"
#include <kernel/console/console.h>
#include <kernel/fs/fs.h>
#include <kernel/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>
#include <kernel/system.h>

#define LSR_DATA_READY 0x1
#define LSR_TRANSMITTER_HOLDING_REGISTER_EMPTY 0x20

static const uint16_t ports[SERIAL_NUM_PORTS] = {
    0x3f8,
    0x2f8,
    0x3e8,
    0x2e8,
};

static void init_port(uint8_t index) {
    uint16_t port = ports[index];
    out8(port + 1, 0x00);
    out8(port + 3, 0x80);
    out8(port + 0, 0x03);
    out8(port + 1, 0x00);
    out8(port + 3, 0x03);
    out8(port + 2, 0xc7);
    out8(port + 4, 0x0b);
}

void serial_early_init(void) { init_port(0); }

static void (*input_handler)(uint8_t, char);

void serial_set_input_handler(void (*handler)(uint8_t, char)) {
    input_handler = handler;
}

static bool sysrq = false;

static bool read_and_report(uint8_t index) {
    uint16_t port = ports[index];
    uint8_t status = in8(port + 5);
    if (status != 0xff && (status & LSR_DATA_READY)) {
        char ch = in8(port);
        if (sysrq)
            handle_sysrq(ch);
        if (input_handler)
            input_handler(index, ch);
        sysrq = status & 0x10; // Break
        return true;
    }
    return false;
}

static void handle_com1_and_com3(registers* regs) {
    (void)regs;
    while (read_and_report(0) || read_and_report(2))
        ;
}

static void handle_com2_and_com4(registers* regs) {
    (void)regs;
    while (read_and_report(1) || read_and_report(3))
        ;
}

static bool is_port_enabled[SERIAL_NUM_PORTS];

static bool enable_port(uint8_t index) {
    init_port(index);
    uint16_t port = ports[index];

    out8(port + 4, 0x1e);
    out8(port + 0, 0xae);

    if (in8(port + 0) != 0xae) {
        kprintf("serial: failed to enable COM%d\n", index + 1);
        return false;
    }

    out8(port + 4, 0x0f);
    out8(port + 1, 0x01);

    switch (index) {
    case 0:
    case 2:
        idt_set_interrupt_handler(IRQ(4), handle_com1_and_com3);
        break;
    case 1:
    case 3:
        idt_set_interrupt_handler(IRQ(3), handle_com2_and_com4);
        break;
    default:
        UNREACHABLE();
    }

    is_port_enabled[index] = true;
    kprintf("serial: enabled COM%d\n", index + 1);
    return true;
}

bool serial_is_port_enabled(uint8_t index) {
    ASSERT(index < SERIAL_NUM_PORTS);
    return is_port_enabled[index];
}

void serial_late_init(void) {
    for (uint8_t i = 0; i < SERIAL_NUM_PORTS; ++i)
        enable_port(i);
}

static void write_char(uint16_t port, char c) {
    while (!(in8(port + 5) & LSR_TRANSMITTER_HOLDING_REGISTER_EMPTY))
        ;
    out8(port, c);
}

void serial_write(uint8_t index, const char* s, size_t count) {
    ASSERT(index < SERIAL_NUM_PORTS);
    uint16_t port = ports[index];

    // This function is called by kprintf, which might be used in critical
    // situations. Thus it is protected by disabling interrupts instead of
    // a mutex.
    bool int_flag = push_cli();

    for (size_t i = 0; i < count; ++i) {
        if (s[i] == '\n')
            write_char(port, '\r');
        write_char(port, s[i]);
    }

    pop_cli(int_flag);
}
