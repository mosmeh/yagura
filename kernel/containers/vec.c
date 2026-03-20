#include <common/integer.h>
#include <common/stdio.h>
#include <common/string.h>
#include <kernel/containers/vec.h>
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

NODISCARD static int grow_capacity(struct vec* vec, size_t requested_capacity) {
    size_t new_capacity = vec->capacity * 2;
    if (new_capacity < vec->capacity)
        return -EOVERFLOW;
    new_capacity = MAX(new_capacity, requested_capacity);
    if (new_capacity == 0)
        new_capacity = PAGE_SIZE;
    new_capacity = ROUND_UP(new_capacity, PAGE_SIZE);
    if (new_capacity == 0)
        return -EOVERFLOW;
    ASSERT(new_capacity > vec->capacity);

    unsigned char* new_buf = krealloc(vec->data, new_capacity);
    if (!new_buf)
        return -ENOMEM;

    vec->data = new_buf;
    vec->capacity = new_capacity;
    return 0;
}

ssize_t vec_pwrite(struct vec* vec, const void* bytes, size_t count,
                   uint64_t offset) {
    uint64_t end = offset + count;
    if (end < offset)
        return -EOVERFLOW;
    if (end > SIZE_MAX)
        return -ENOSPC;
    if (end > vec->capacity) {
        int rc = grow_capacity(vec, end);
        if (IS_ERR(rc))
            return rc;
    }

    if (offset > vec->size)
        memset(vec->data + vec->size, 0, offset - vec->size);
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
    char* buf = vec->data ? (char*)(vec->data + vec->size) : NULL;
    size_t remaining_capacity = vec->capacity - vec->size;
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(buf, remaining_capacity, format, args_copy);
    va_end(args_copy);
    if (len < 0)
        return -EINVAL;
    if ((size_t)len < remaining_capacity) {
        vec->size += len;
        return len;
    }
    int rc = grow_capacity(vec, vec->size + len + 1);
    if (IS_ERR(rc))
        return rc;

    ASSERT_PTR(vec->data);
    buf = (char*)(vec->data + vec->size);
    remaining_capacity = vec->capacity - vec->size;
    len = vsnprintf(buf, remaining_capacity, format, args);
    ASSERT(len >= 0);
    ASSERT((size_t)len < remaining_capacity);
    vec->size += len;
    return len;
}
