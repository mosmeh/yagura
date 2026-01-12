#pragma once

#include <kernel/api/signal.h>

struct registers {
    unsigned long gs, fs, es, ds;
#ifdef ARCH_X86_64
    unsigned long r15, r14, r13, r12;
    unsigned long r11, r10, r9, r8;
#endif
    unsigned long bp, di, si, dx, cx, bx, ax;
    unsigned long interrupt_num, error_code;
    unsigned long ip, cs, flags, sp, ss;
};

struct sigcontext {
    sigset_t blocked_signals;
    struct registers regs;
#ifdef ARCH_I386
    unsigned char trampoline[8];
#endif
#ifdef ARCH_X86_64
    unsigned char trampoline[10];
#endif
};
