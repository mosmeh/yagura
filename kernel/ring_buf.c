#include "ring_buf.h"
#include "api/errno.h"
#include "memory/memory.h"

#define BUF_CAPACITY 1024

int ring_buf_init(ring_buf* buf) {
    mutex_init(&buf->lock);
    buf->inner_buf = kmalloc(BUF_CAPACITY);
    if (!buf->inner_buf)
        return -ENOMEM;
    atomic_init(&buf->write_idx, 0);
    atomic_init(&buf->read_idx, 0);
    return 0;
}

void ring_buf_destroy(ring_buf* buf) { kfree(buf->inner_buf); }

bool ring_buf_is_empty(const ring_buf* buf) {
    return atomic_load_explicit(&buf->write_idx, memory_order_acquire) ==
           atomic_load_explicit(&buf->read_idx, memory_order_acquire);
}

bool ring_buf_is_full(const ring_buf* buf) {
    size_t write_idx =
        atomic_load_explicit(&buf->write_idx, memory_order_acquire);
    size_t read_idx =
        atomic_load_explicit(&buf->read_idx, memory_order_acquire);
    return (write_idx + 1) % BUF_CAPACITY == read_idx;
}

ssize_t ring_buf_read(ring_buf* buf, void* buffer, size_t count) {
    size_t nread = 0;
    unsigned char* dest = buffer;
    const unsigned char* src = buf->inner_buf;
    size_t read_idx =
        atomic_load_explicit(&buf->read_idx, memory_order_acquire);
    size_t write_idx =
        atomic_load_explicit(&buf->write_idx, memory_order_acquire);
    while (nread < count) {
        dest[nread++] = src[read_idx];
        read_idx = (read_idx + 1) % BUF_CAPACITY;
        if (read_idx == write_idx)
            break;
    }
    atomic_store_explicit(&buf->read_idx, read_idx, memory_order_release);
    return nread;
}

ssize_t ring_buf_write(ring_buf* buf, const void* buffer, size_t count) {
    size_t nwritten = 0;
    unsigned char* dest = buf->inner_buf;
    const unsigned char* src = buffer;
    size_t write_idx =
        atomic_load_explicit(&buf->write_idx, memory_order_acquire);
    size_t read_idx =
        atomic_load_explicit(&buf->read_idx, memory_order_acquire);
    while (nwritten < count) {
        dest[write_idx] = src[nwritten++];
        write_idx = (write_idx + 1) % BUF_CAPACITY;
        if ((write_idx + 1) % BUF_CAPACITY == read_idx)
            break;
    }
    atomic_store_explicit(&buf->write_idx, write_idx, memory_order_release);
    return nwritten;
}

ssize_t ring_buf_write_evicting_oldest(ring_buf* buf, const void* buffer,
                                       size_t count) {
    size_t nwritten = 0;
    unsigned char* dest = buf->inner_buf;
    const unsigned char* src = buffer;
    size_t write_idx =
        atomic_load_explicit(&buf->write_idx, memory_order_acquire);
    while (nwritten < count) {
        dest[write_idx] = src[nwritten++];
        write_idx = (write_idx + 1) % BUF_CAPACITY;
    }
    atomic_store_explicit(&buf->write_idx, write_idx, memory_order_release);
    return nwritten;
}
