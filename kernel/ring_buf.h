#include "api/sys/types.h"
#include <common/extra.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>

struct ring_buf {
    size_t capacity;
    atomic_size_t write_index;
    atomic_size_t read_index;
    unsigned char* ring;
};

NODISCARD int ring_buf_init(struct ring_buf*, size_t capacity);
void ring_buf_destroy(struct ring_buf*);
bool ring_buf_is_empty(const struct ring_buf*);
bool ring_buf_is_full(const struct ring_buf*);
NODISCARD ssize_t ring_buf_read(struct ring_buf*, void* bytes, size_t count);
NODISCARD ssize_t ring_buf_write(struct ring_buf*, const void* bytes,
                                 size_t count);
ssize_t ring_buf_write_evicting_oldest(struct ring_buf*, const void* bytes,
                                       size_t count);
void ring_buf_clear(struct ring_buf*);
