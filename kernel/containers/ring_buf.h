#pragma once

#include <kernel/api/errno.h>
#include <kernel/api/sys/types.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/safe_string.h>

struct ring_buf {
    size_t len;
    _Atomic(size_t) write_index;
    _Atomic(size_t) read_index;
    unsigned char ring[];
};

NODISCARD static inline struct ring_buf* ring_buf_create(size_t capacity) {
    // Allocate one extra byte to distinguish full vs empty
    size_t len = capacity + 1;
    struct ring_buf* b =
        kmalloc(sizeof(struct ring_buf) + len * sizeof(unsigned char));
    if (!b)
        return NULL;
    *b = (struct ring_buf){.len = len};
    return b;
}

static inline void ring_buf_destroy(struct ring_buf* b) { kfree(b); }

DEFINE_FREE(ring_buf, struct ring_buf*, ring_buf_destroy)

static inline bool ring_buf_is_empty(const struct ring_buf* b) {
    return b->write_index == b->read_index;
}

static inline bool ring_buf_is_full(const struct ring_buf* b) {
    return (b->write_index + 1) % b->len == b->read_index;
}

NODISCARD static inline ssize_t ring_buf_read(struct ring_buf* b, void* bytes,
                                              size_t count) {
    size_t nread = 0;
    unsigned char* dest = bytes;
    const unsigned char* src = b->ring;
    while (nread < count) {
        if (ring_buf_is_empty(b))
            break;
        dest[nread++] = src[b->read_index];
        b->read_index = (b->read_index + 1) % b->len;
    }
    return nread;
}

NODISCARD static inline ssize_t
ring_buf_read_to_user(struct ring_buf* b, void* user_bytes, size_t count) {
    size_t nread = 0;
    unsigned char* user_dest = user_bytes;
    const unsigned char* src = b->ring;
    while (nread < count) {
        if (ring_buf_is_empty(b))
            break;
        if (copy_to_user(user_dest + nread, &src[b->read_index],
                         sizeof(unsigned char)))
            return -EFAULT;
        ++nread;
        b->read_index = (b->read_index + 1) % b->len;
    }
    return nread;
}

NODISCARD static inline ssize_t
ring_buf_write(struct ring_buf* b, const void* bytes, size_t count) {
    size_t nwritten = 0;
    unsigned char* dest = b->ring;
    const unsigned char* src = bytes;
    while (nwritten < count) {
        if (ring_buf_is_full(b))
            break;
        dest[b->write_index] = src[nwritten++];
        b->write_index = (b->write_index + 1) % b->len;
    }
    return nwritten;
}

NODISCARD static inline ssize_t ring_buf_write_from_user(struct ring_buf* b,
                                                         const void* user_bytes,
                                                         size_t count) {
    size_t nwritten = 0;
    unsigned char* dest = b->ring;
    const unsigned char* user_src = user_bytes;
    while (nwritten < count) {
        if (ring_buf_is_full(b))
            break;
        if (copy_from_user(&dest[b->write_index], user_src + nwritten,
                           sizeof(unsigned char)))
            return -EFAULT;
        ++nwritten;
        b->write_index = (b->write_index + 1) % b->len;
    }
    return nwritten;
}

static inline ssize_t ring_buf_write_evicting_oldest(struct ring_buf* b,
                                                     const void* bytes,
                                                     size_t count) {
    size_t nwritten = 0;
    unsigned char* dest = b->ring;
    const unsigned char* src = bytes;
    while (nwritten < count) {
        dest[b->write_index] = src[nwritten++];
        b->write_index = (b->write_index + 1) % b->len;
        if (b->write_index == b->read_index)
            b->read_index = (b->read_index + 1) % b->len;
    }
    return nwritten;
}

static inline void ring_buf_clear(struct ring_buf* b) {
    b->write_index = b->read_index = 0;
}
