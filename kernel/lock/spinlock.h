#pragma once

#include <kernel/lock/lock.h>

struct spinlock {
    _Atomic(unsigned int) lock;
};

DEFINE_LOCK(spinlock)
DEFINE_LOCK_GUARD(spinlock, struct spinlock)
