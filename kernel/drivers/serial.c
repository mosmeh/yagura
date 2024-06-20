#include "serial.h"
#include <kernel/console/console.h>
#include <kernel/fs/fs.h>
#include <kernel/interrupts.h>
#include <kernel/kprintf.h>
#include <kernel/panic.h>
#include <kernel/system.h>

static void init_port(uint16_t port) {
    out8(port + 1, 0x00);
    out8(port + 3, 0x80);
    out8(port + 0, 0x03);
    out8(port + 1, 0x00);
    out8(port + 3, 0x03);
    out8(port + 2, 0xc7);
    out8(port + 4, 0x0b);
}

void serial_early_init(void) { init_port(SERIAL_COM1); }

#define DATA_READY 0x1
#define TRANSMITTER_HOLDING_REGISTER_EMPTY 0x20

static bool sysrq = false;

static bool read_and_report(uint16_t port) {
    uint8_t status = in8(port + 5);
    if (status != 0xff && (status & 1)) {
        char ch = in8(port);
        if (sysrq)
            handle_sysrq(ch);
        sysrq = status & 0x10; // Break
        serial_console_on_char(port, ch);
        return true;
    }
    return false;
}

static void handle_1_and_3(registers* regs) {
    (void)regs;
    while (read_and_report(SERIAL_COM1) || read_and_report(SERIAL_COM3))
        ;
}

static void handle_2_and_4(registers* regs) {
    (void)regs;
    while (read_and_report(SERIAL_COM2) || read_and_report(SERIAL_COM4))
        ;
}

static bool is_port_enabled[4];

static bool enable_port(uint16_t port) {
    if (!serial_is_valid_port(port))
        return false;
    uint8_t com_number = serial_port_to_com_number(port);

    init_port(port);

    out8(port + 4, 0x1e);
    out8(port + 0, 0xae);

    if (in8(port + 0) != 0xae) {
        kprintf("serial: failed to enable COM%d\n", com_number);
        return false;
    }

    out8(port + 4, 0x0f);
    out8(port + 1, 0x01);

    switch (port) {
    case SERIAL_COM1:
    case SERIAL_COM3:
        idt_set_interrupt_handler(IRQ(4), handle_1_and_3);
        break;
    case SERIAL_COM2:
    case SERIAL_COM4:
        idt_set_interrupt_handler(IRQ(3), handle_2_and_4);
        break;
    default:
        UNREACHABLE();
    }

    is_port_enabled[com_number - 1] = true;
    kprintf("serial: enabled COM%d\n", com_number);
    return true;
}

bool serial_is_port_enabled(uint16_t port) {
    return is_port_enabled[serial_port_to_com_number(port) - 1];
}

void serial_late_init(void) {
    enable_port(SERIAL_COM1);
    enable_port(SERIAL_COM2);
    enable_port(SERIAL_COM3);
    enable_port(SERIAL_COM4);
}

static void write_char(uint16_t port, char c) {
    while (!(in8(port + 5) & TRANSMITTER_HOLDING_REGISTER_EMPTY))
        ;
    out8(port, c);
}

size_t serial_write(uint16_t port, const char* s, size_t count) {
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
    return count;
}
