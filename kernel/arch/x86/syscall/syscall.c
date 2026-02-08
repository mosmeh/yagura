#include <kernel/arch/x86/syscall/syscall.h>

void syscall_init(void) {
    void syscall_init_int80(void);
    syscall_init_int80();

#ifdef ARCH_X86_64
    void syscall_init_syscall(void);
    syscall_init_syscall();
#endif
}
