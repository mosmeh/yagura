#pragma once

#include <common/extra.h>
#include <kernel/api/sys/types.h>
#include <stdarg.h>
#include <stdatomic.h>

struct vec {
    unsigned char* data;
    atomic_size_t capacity, size;
};

void vec_destroy(struct vec*);

// Reserves capacity for at least `additional` bytes.
NODISCARD int vec_reserve(struct vec*, size_t additional);

// Resizes the buffer to `length`. If the buffer is grown, the new bytes are
// zeroed.
NODISCARD int vec_resize(struct vec*, off_t new_size);

NODISCARD ssize_t vec_pread(struct vec*, void* bytes, size_t count,
                            off_t offset);
NODISCARD ssize_t vec_pwrite(struct vec*, const void* bytes, size_t count,
                             off_t offset);
NODISCARD ssize_t vec_append(struct vec*, const void* bytes, size_t count);

NODISCARD void* vec_mmap(struct vec*, size_t length, off_t offset, int flags);

int vec_printf(struct vec*, const char* format, ...) PRINTF_LIKE(2, 3);
int vec_vsprintf(struct vec*, const char* format, va_list args)
    PRINTF_LIKE(2, 0);
