#include <kernel/process.h>

noreturn uintptr_t sys_exit(int status) { process_exit(status); }

uintptr_t sys_fork(registers* regs) { return process_userland_fork(regs); }

uintptr_t sys_getpid(void) { return process_get_pid(); }

uintptr_t sys_yield(void) {
    process_switch();
    return 0;
}
