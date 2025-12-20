#pragma once

#include <common/macros.h>
#include <kernel/api/errno.h>
#include <stdbool.h>
#include <stdint.h>

// Casts error value to pointer
#define ERR_PTR(x) ((void*)(x))

// Casts pointer to error value
#define PTR_ERR(x) ((long)(x))

// Valid pointers never point to the last page of the address space.
// We use this fact to encode error values in pointers.
#define IS_ERR(x) ((uintptr_t)(x) > (uintptr_t)(-4096))
STATIC_ASSERT(IS_ERR(-EMAXERRNO));

static inline bool IS_ERR_OR_NULL(const volatile void* ptr) {
    return !ptr || IS_ERR(ptr);
}

#define IS_OK(x) (!IS_ERR(x))

// Casts error-valued pointer to pointer of another type
#define ERR_CAST(x) ((void*)(x))
