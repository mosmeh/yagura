#include "kprintf.h"
#include "asm_wrapper.h"
#include "interrupts.h"
#include "serial.h"
#include <stdarg.h>
#include <stdio.h>

int kputs(const char* str) {
    bool int_flag = push_cli();

    int i = 0;
    while (*str) {
        serial_write(SERIAL_COM1, *str++);
        ++i;
    }

    pop_cli(int_flag);
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
