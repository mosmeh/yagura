#pragma once

#include <kernel/api/sched.h>

int clone(int (*fn)(void*), void* stack, int flags, void* arg, ...);

int sched_yield(void);
