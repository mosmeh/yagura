#pragma once

#include <common/stdint.h>

extern uintptr_t __stack_chk_guard;

#if UINTPTR_MAX == UINT64_MAX
// Clear the second byte to prevent string functions to read/write past
// the canary, while still detecting the corruption of the first byte.
// 64-bit canaries have still have enough entropy in the remaining bytes.
#define __CANARY_MASK 0xffffffffffff00ff
#else
#define __CANARY_MASK ~0UL
#endif

#define STACK_CHK_GUARD_INIT(canary)                                           \
    do {                                                                       \
        __stack_chk_guard = (canary) & __CANARY_MASK;                          \
    } while (0)
