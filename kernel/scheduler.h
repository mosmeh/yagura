#pragma once

#include "forward.h"
#include <stdbool.h>

void scheduler_init(void);

void scheduler_yield(bool requeue_current);
void scheduler_enqueue(process*);
void scheduler_block(bool (*should_unblock)(), void* data);
