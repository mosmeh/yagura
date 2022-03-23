#include "kprintf.h"
#include "asm_wrapper.h"
#include "serial.h"
#include <common/string.h>

int kputchar(int c) {
    uint32_t eflags = read_eflags();
    cli();
    serial_write(SERIAL_COM1, c);
    if (eflags & 0x200)
        sti();
    return c;
}

int kputs(const char* str) {
    uint32_t eflags = read_eflags();
    cli();
    int i = 0;
    while (*str) {
        kputchar(*str++);
        ++i;
    }
    if (eflags & 0x200)
        sti();
    return i;
}

int kprintf(const char* format, ...) {
    char buf[1024];
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buf, 1024, format, args);
    va_end(args);
    kputs(buf);
    return ret;
}
