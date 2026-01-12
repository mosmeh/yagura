#pragma once

#include <kernel/arch/x86/gdt.h>

struct fpu_state {
    _Alignas(16) unsigned char buffer[512];
};

struct arch_task {
    uintptr_t ip, sp;
    struct gdt_segment tls[NUM_GDT_TLS_ENTRIES];
    struct fpu_state fpu_state;
};
