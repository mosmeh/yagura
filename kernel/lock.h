#pragma once

#include <stdatomic.h>
#include <stdint.h>

struct mutex {
    volatile struct process* holder;
    volatile uint32_t level;
    volatile atomic_bool lock;
};

void mutex_lock(struct mutex*);
void mutex_unlock(struct mutex*);

struct spinlock {
    uint32_t level;
    volatile atomic_uint lock;
};

void spinlock_lock(struct spinlock*);
void spinlock_unlock(struct spinlock*);
