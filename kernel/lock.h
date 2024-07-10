#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

struct mutex {
    volatile struct process* holder;
    volatile uint32_t level;
    volatile atomic_bool lock;
};

void mutex_lock(struct mutex*);
void mutex_unlock(struct mutex*);
bool mutex_unlock_if_locked(struct mutex* m);
