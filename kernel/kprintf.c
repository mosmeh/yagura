#include "kprintf.h"
#include "drivers/serial.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

int kprint(const char* str) {
    return serial_write(SERIAL_COM1, str, strlen(str));
}

int kprintf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = kvprintf(format, args);
    va_end(args);
    return ret;
}

int kvprintf(const char* format, va_list args) {
    char buf[1024];
    int ret = vsnprintf(buf, sizeof(buf), format, args);
    kprint(buf);
    return ret;
}
