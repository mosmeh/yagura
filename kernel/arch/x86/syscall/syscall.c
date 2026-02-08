#include <kernel/arch/x86/syscall/syscall.h>

void syscall_init_int80(void);

void syscall_init(void) {
    syscall_init_int80();
    syscall_init_cpu();
}

void syscall_init_cpu(void) {
#ifdef ARCH_X86_64
    void syscall_init_syscall(void);
    syscall_init_syscall();
#endif
}
