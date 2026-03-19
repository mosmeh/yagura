#pragma once

#include <common/macros.h>
#include <common/stdbool.h>
#include <common/stdint.h>
#include <kernel/api/errno.h>

// Casts error value to pointer
NODISCARD static inline void* ERR_PTR(long error) { return (void*)error; }

// Casts pointer to error value
NODISCARD static inline long PTR_ERR(const void* ptr) { return (long)ptr; }

// Valid pointers never point to the last page of the address space.
// We use this fact to encode error values in pointers.
#define IS_ERR(x) ((uintptr_t)(x) > (uintptr_t)(-4096))
STATIC_ASSERT(IS_ERR(-EMAXERRNO));

NODISCARD static inline bool IS_ERR_OR_NULL(const volatile void* ptr) {
    return !ptr || IS_ERR(ptr);
}

#define IS_OK(x) (!IS_ERR(x))

// Casts error-valued pointer to pointer of another type
NODISCARD static inline void* ERR_CAST(const void* ptr) { return (void*)ptr; }
