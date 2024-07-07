#pragma once

#include <common/extra.h>
#include <stdatomic.h>
#include <stdbool.h>

struct process;

extern atomic_uint idle_ticks;

void scheduler_init(void);

void scheduler_yield(bool requeue_current);
void scheduler_register(struct process*);
void scheduler_enqueue(struct process*);
void scheduler_tick(bool in_kernel);

#define BLOCK_UNINTERRUPTIBLE 1

// Returns true if the process should be unblocked.
typedef bool (*unblock_fn)(void*);

// Blocks the current process until the unblock function returns true.
// Returns -EINTR if the process was interrupted.
NODISCARD int scheduler_block(unblock_fn, void* data, int flags);
