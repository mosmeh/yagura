#pragma once

#include <kernel/lock/lock.h>

struct mutex {
    _Atomic(struct task*) holder;
    unsigned int level;
};

DEFINE_LOCK(mutex)
DEFINE_LOCK_GUARD(mutex, struct mutex)
