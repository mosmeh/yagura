#pragma once

#include <kernel/arch/x86/gdt.h>

struct fpu_state {
    _Alignas(16) unsigned char buffer[512];
};

struct arch_task {
    uintptr_t ip, sp;
#ifdef ARCH_X86_64
    uintptr_t fs_base, gs_base;
#endif
    struct gdt_segment tls[NUM_GDT_TLS_ENTRIES];
    struct fpu_state fpu_state;
};
