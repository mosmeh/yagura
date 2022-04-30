#pragma once

#include "api/sys/types.h"
#include "forward.h"
#include <stdbool.h>

void scheduler_init(void);

void scheduler_yield(bool requeue_current);
void scheduler_register(struct process*);
void scheduler_unregister(struct process*);
void scheduler_enqueue(struct process*);
void scheduler_block(bool (*should_unblock)(), void* data);
