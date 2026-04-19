#pragma once

#include <common/macros.h>
#include <common/stdbool.h>
#include <kernel/api/linux/futex.h>
#include <kernel/api/sys/types.h>

struct timespec;

NODISCARD long futex(uint32_t* uaddr, int op, uint32_t val,
                     const struct timespec* timeout, uint32_t* uaddr2,
                     uint32_t val3);

// Tests whether the 32-bit value at uaddr is equal to val, and if so,
// sleeps until either a FUTEX_WAKE operation wakes it or the timeout elapses.
NODISCARD int futex_wait(uint32_t* uaddr, uint32_t val,
                         const struct timespec* timeout, int flags);

// Like `futex_wait` but with a bitset argument that can be used to wake only a
// subset of waiters.
NODISCARD int futex_wait_bitset(uint32_t* uaddr, uint32_t val,
                                const struct timespec* deadline,
                                uint32_t bitset, int flags);

// Wakes up at most val tasks waiting on the futex at uaddr.
// Returns the number of tasks that were woken up.
NODISCARD ssize_t futex_wake(uint32_t* uaddr, uint32_t val, int flags);

// Like `futex_wake` except it wakes only waiters whose bitset ANDed with
// the given bitset is nonzero.
NODISCARD ssize_t futex_wake_bitset(uint32_t* uaddr, uint32_t val,
                                    uint32_t bitset, int flags);

bool futex_op_has_timeout(int op);
