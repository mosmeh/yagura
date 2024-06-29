#include "growable_buf.h"
#include "api/err.h"
#include "boot_defs.h"
#include "memory/memory.h"
#include "panic.h"
#include <stdio.h>
#include <string.h>

void growable_buf_destroy(growable_buf* buf) { kfree(buf->addr); }

ssize_t growable_buf_pread(growable_buf* buf, void* bytes, size_t count,
                           off_t offset) {
    if ((size_t)offset >= buf->size)
        return 0;
    if (offset + count >= buf->size)
        count = buf->size - offset;

    memcpy(bytes, buf->addr + offset, count);
    return count;
}

NODISCARD static int grow_buf(growable_buf* buf, size_t requested_size) {
    size_t new_capacity = buf->capacity * 2;
    if (new_capacity < buf->capacity)
        return -EOVERFLOW;
    new_capacity = MAX(new_capacity, requested_size);
    if (new_capacity == 0)
        new_capacity = PAGE_SIZE;
    new_capacity = round_up(new_capacity, PAGE_SIZE);
    if (new_capacity == 0)
        return -EOVERFLOW;
    ASSERT(new_capacity > buf->capacity);

    unsigned char* new_addr = krealloc(buf->addr, new_capacity);
    if (!new_addr)
        return -ENOMEM;

    memset(new_addr + buf->size, 0, new_capacity - buf->size);

    buf->addr = new_addr;
    buf->capacity = new_capacity;
    return 0;
}

ssize_t growable_buf_pwrite(growable_buf* buf, const void* bytes, size_t count,
                            off_t offset) {
    size_t end = offset + count;
    if (end > buf->capacity) {
        int rc = grow_buf(buf, end);
        if (IS_ERR(rc))
            return rc;
    }

    memcpy(buf->addr + offset, bytes, count);
    if (buf->size < end)
        buf->size = end;

    return count;
}

ssize_t growable_buf_append(growable_buf* buf, const void* bytes,
                            size_t count) {
    return growable_buf_pwrite(buf, bytes, count, buf->size);
}

int growable_buf_truncate(growable_buf* buf, off_t length) {
    if ((size_t)length <= buf->size) {
        memset(buf->addr + length, 0, buf->size - length);
    } else if ((size_t)length <= buf->capacity) {
        memset(buf->addr + buf->size, 0, length - buf->size);
    } else {
        // length > capacity
        int rc = grow_buf(buf, length);
        if (IS_ERR(rc))
            return rc;
    }

    buf->size = length;
    return 0;
}

void* growable_buf_mmap(growable_buf* buf, size_t length, off_t offset,
                        int flags) {
    if (offset != 0)
        return ERR_PTR(-ENOTSUP);
    if (length > buf->size)
        return ERR_PTR(-EINVAL);
    return vm_virt_map(buf->addr, length, flags);
}

int growable_buf_printf(growable_buf* buf, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = growable_buf_vsprintf(buf, format, args);
    va_end(args);
    return ret;
}

int growable_buf_vsprintf(growable_buf* buf, const char* format, va_list args) {
    for (;;) {
        size_t max_len = buf->capacity - buf->size;
        if (max_len > 0) {
            char* dest = (char*)(buf->addr + buf->size);
            int len = vsnprintf(dest, max_len, format, args);
            if ((size_t)len < max_len) {
                buf->size += len;
                return len;
            }
        }
        int rc = grow_buf(buf, 0); // specify 0 to let grow_buf decide size
        if (IS_ERR(rc))
            return rc;
    }
}
