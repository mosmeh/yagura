#include "panic.h"
#include "stdio.h"
#include "stdlib.h"
#include "unistd.h"

noreturn void panic(const char* file, size_t line, const char* format, ...) {
    dprintf(STDERR_FILENO, "PANIC: ");
    va_list args;
    va_start(args, format);
    vdprintf(STDERR_FILENO, format, args);
    va_end(args);
    dprintf(STDERR_FILENO, " at %s:%u\n", file, line);
    abort();
}
