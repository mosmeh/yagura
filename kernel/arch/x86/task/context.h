#pragma once

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
