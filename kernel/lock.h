#pragma once

#include <stdatomic.h>
#include <stdint.h>

typedef struct mutex {
    volatile struct process* holder;
    volatile uint32_t level;
    volatile atomic_bool lock;
} mutex;

void mutex_lock(mutex*);
void mutex_unlock(mutex*);
