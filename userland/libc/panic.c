#include <panic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void panic(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vdprintf(STDERR_FILENO, format, args);
    va_end(args);
    abort();
}
