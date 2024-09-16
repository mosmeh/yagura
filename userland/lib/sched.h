#pragma once

#include <kernel/api/sched.h>

int clone(int (*fn)(void*), void* stack, int flags, void* arg, ...
          /* pid_t* parent_tid, void* tls */);

int sched_yield(void);

int getcpu(unsigned int* cpu, unsigned int* node);
