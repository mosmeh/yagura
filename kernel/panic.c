#include "panic.h"
#include "asm_wrapper.h"
#include "kprintf.h"

noreturn void kpanic(const char* message, const char* file, size_t line) {
    kprintf("%s at %s:%u\n", message, file, line);
    cli();
    for (;;)
        hlt();
}
