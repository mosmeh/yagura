#pragma once

#include "api/types.h"
#include "forward.h"
#include <stdbool.h>

void scheduler_init(void);

process* scheduler_find_process_by_pid(pid_t);
void scheduler_yield(bool requeue_current);
void scheduler_enqueue(process*);
void scheduler_block(bool (*should_unblock)(), void* data);
