#include "api/types.h"
#include "lock.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct ring_buf {
    mutex lock;
    void* inner_buf;
    atomic_size_t write_idx;
    atomic_size_t read_idx;
} ring_buf;

int ring_buf_init(ring_buf*);
bool ring_buf_is_empty(ring_buf*);
bool ring_buf_is_full(ring_buf*);
ssize_t ring_buf_write(ring_buf*, const void* buffer, size_t count);
ssize_t ring_buf_read(ring_buf*, void* buffer, size_t count);
