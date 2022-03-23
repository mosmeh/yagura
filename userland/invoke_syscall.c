#include "syscall.h"
#include <common/extra.h>
#include <common/syscall.h>

uintptr_t invoke_syscall(uint32_t num, uintptr_t arg1, uintptr_t arg2) {
    uintptr_t ret;
    __asm__ volatile("int $" STRINGIFY(SYSCALL_VECTOR)
                     : "=a"(ret)
                     : "a"(num), "d"(arg1), "c"(arg2));
    return ret;
}
