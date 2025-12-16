#include "vec.h"
#include <common/stdio.h>
#include <common/string.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

void vec_deinit(struct vec* vec) {
    kfree(vec->data);
    *vec = (struct vec){0};
}

ssize_t vec_pread(struct vec* vec, void* bytes, size_t count, uint64_t offset) {
    if (offset >= vec->size)
        return 0;
    if (offset + count >= vec->size)
        count = vec->size - offset;

    memcpy(bytes, vec->data + offset, count);
    return count;
}

NODISCARD static int grow_capacity(struct vec* vec, size_t requested_size) {
    size_t new_capacity = vec->capacity * 2;
    if (new_capacity < vec->capacity)
        return -EOVERFLOW;
    new_capacity = MAX(new_capacity, requested_size);
    if (new_capacity == 0)
        new_capacity = PAGE_SIZE;
    new_capacity = ROUND_UP(new_capacity, PAGE_SIZE);
    if (new_capacity == 0)
        return -EOVERFLOW;
    ASSERT(new_capacity > vec->capacity);

    unsigned char* new_buf = krealloc(vec->data, new_capacity);
    if (!new_buf)
        return -ENOMEM;

    memset(new_buf + vec->size, 0, new_capacity - vec->size);

    vec->data = new_buf;
    vec->capacity = new_capacity;
    return 0;
}

ssize_t vec_pwrite(struct vec* vec, const void* bytes, size_t count,
                   uint64_t offset) {
    uint64_t end = offset + count;
    if (end > vec->capacity) {
        int rc = grow_capacity(vec, end);
        if (IS_ERR(rc))
            return rc;
    }

    memcpy(vec->data + offset, bytes, count);
    if (vec->size < end)
        vec->size = end;

    return count;
}

ssize_t vec_append(struct vec* vec, const void* bytes, size_t count) {
    return vec_pwrite(vec, bytes, count, vec->size);
}

int vec_printf(struct vec* vec, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vec_vsprintf(vec, format, args);
    va_end(args);
    return ret;
}

int vec_vsprintf(struct vec* vec, const char* format, va_list args) {
    for (;;) {
        uint64_t max_len = vec->capacity - vec->size;
        if (max_len > 0) {
            char* dest = (char*)(vec->data + vec->size);
            int len = vsnprintf(dest, max_len, format, args);
            if ((uint64_t)len < max_len) {
                vec->size += len;
                return len;
            }
        }
        int rc =
            grow_capacity(vec, 0); // specify 0 to let grow_capacity decide size
        if (IS_ERR(rc))
            return rc;
    }
}
