#pragma once

#include <common/macros.h>
#include <common/stdarg.h>
#include <common/stddef.h>
#include <kernel/api/sys/types.h>

struct vec {
    unsigned char* data;
    uint64_t capacity, size;
};

void vec_deinit(struct vec*);

NODISCARD ssize_t vec_pread(struct vec*, void* bytes, size_t count,
                            uint64_t offset);
NODISCARD ssize_t vec_pwrite(struct vec*, const void* bytes, size_t count,
                             uint64_t offset);
NODISCARD ssize_t vec_append(struct vec*, const void* bytes, size_t count);

NODISCARD int vec_printf(struct vec*, const char* format, ...)
    PRINTF_LIKE(2, 3);
NODISCARD int vec_vsprintf(struct vec*, const char* format, va_list args)
    PRINTF_LIKE(2, 0);
