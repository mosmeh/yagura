#include <kernel/api/sys/syscall.h>

    .text
    .global signal_trampoline_start, signal_trampoline_end
signal_trampoline_start:
    popl %eax # pop signum
    movl $SYS_sigreturn, %eax
    int $SYSCALL_VECTOR
signal_trampoline_end:
