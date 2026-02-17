#pragma once

#include <kernel/cpu.h>

static inline void smap_begin_user_access(void) {
    if (cpu_has_feature(cpu_get_bsp(), X86_FEATURE_SMAP))
        __asm__ volatile("stac" ::: "memory");
}

static inline void smap_end_user_access(void) {
    if (cpu_has_feature(cpu_get_bsp(), X86_FEATURE_SMAP))
        __asm__ volatile("clac" ::: "memory");
}
