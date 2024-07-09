#include "ring_buf.h"
#include "api/errno.h"
#include "memory/memory.h"

int ring_buf_init(ring_buf* b, size_t capacity) {
    *b = (ring_buf){0};
    b->capacity = capacity;
    b->write_index = b->read_index = 0;
    b->ring = kmalloc(capacity);
    if (!b->ring)
        return -ENOMEM;
    return 0;
}

void ring_buf_destroy(ring_buf* b) { kfree(b->ring); }

bool ring_buf_is_empty(const ring_buf* b) {
    return b->write_index == b->read_index;
}

bool ring_buf_is_full(const ring_buf* b) {
    return (b->write_index + 1) % b->capacity == b->read_index;
}

ssize_t ring_buf_read(ring_buf* b, void* bytes, size_t count) {
    size_t nread = 0;
    unsigned char* dest = bytes;
    const unsigned char* src = b->ring;
    while (nread < count) {
        dest[nread++] = src[b->read_index];
        b->read_index = (b->read_index + 1) % b->capacity;
        if (b->read_index == b->write_index)
            break;
    }
    return nread;
}

ssize_t ring_buf_write(ring_buf* b, const void* bytes, size_t count) {
    size_t nwritten = 0;
    unsigned char* dest = b->ring;
    const unsigned char* src = bytes;
    while (nwritten < count) {
        dest[b->write_index] = src[nwritten++];
        b->write_index = (b->write_index + 1) % b->capacity;
        if ((b->write_index + 1) % b->capacity == b->read_index)
            break;
    }
    return nwritten;
}

ssize_t ring_buf_write_evicting_oldest(ring_buf* b, const void* bytes,
                                       size_t count) {
    size_t nwritten = 0;
    unsigned char* dest = b->ring;
    const unsigned char* src = bytes;
    while (nwritten < count) {
        dest[b->write_index] = src[nwritten++];
        b->write_index = (b->write_index + 1) % b->capacity;
        if (b->write_index == b->read_index)
            b->read_index = (b->read_index + 1) % b->capacity;
    }
    return nwritten;
}

void ring_buf_clear(ring_buf* b) { b->write_index = b->read_index = 0; }
