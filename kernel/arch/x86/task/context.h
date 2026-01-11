#pragma once

#include <kernel/api/signal.h>

struct registers {
    unsigned long gs, fs, es, ds;
    unsigned long bp, di, si, dx, cx, bx, ax;
    unsigned long interrupt_num, error_code;
    unsigned long ip, cs, flags, sp, ss;
};

struct sigcontext {
    sigset_t blocked_signals;
    struct registers regs;
    unsigned char trampoline[8];
};
