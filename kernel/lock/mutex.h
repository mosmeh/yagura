#pragma once

#include <kernel/lock/lock.h>
#include <kernel/task/sched.h>

struct mutex {
    struct waitqueue wait;
    _Atomic(struct task*) holder;
    unsigned int level;
};

DEFINE_LOCK(mutex)
DEFINE_LOCK_GUARD(mutex, struct mutex)
