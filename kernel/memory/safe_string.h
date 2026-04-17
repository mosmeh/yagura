#pragma once

#include <common/macros.h>
#include <common/stddef.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/types.h>

// Safe string functions that can handle untrusted pointers without causing page
// faults.

// Copies n bytes from src to dest. Returns 0 on success, -EFAULT on failure.
NODISCARD int safe_memcpy(void* dest, const void* src, size_t n);

// Sets n bytes of s to c. Returns 0 on success, -EFAULT on failure.
NODISCARD int safe_memset(void* s, unsigned char c, size_t n);

// Gets the length of a string in kernel space.
// Returns the shorter of the string length and n, or -EFAULT on failure.
NODISCARD ssize_t safe_strnlen(const char* str, size_t n);

// Copies n bytes from src to dest.
// If the string is shorter than n, the rest of the dest buffer is zeroed.
// Returns the shorter of the string length and n, or -EFAULT on failure.
NODISCARD ssize_t safe_strncpy(char* dest, const char* src, size_t n);

// Atomically loads a 32-bit value from the given pointer.
// Returns 0 on success, -EINVAL if the pointer is not 4-byte aligned,
// or -EFAULT on failure.
NODISCARD int safe_atomic_load_u32(const uint32_t* ptr, uint32_t* out);

// Atomically stores a 32-bit value to the given pointer.
// Returns 0 on success, -EINVAL if the pointer is not 4-byte aligned,
// or -EFAULT on failure.
NODISCARD int safe_atomic_store_u32(uint32_t* ptr, uint32_t value);

// Copies data from user space to kernel space.
// Returns 0 on success, -EFAULT on failure.
NODISCARD int copy_from_user(void* to, const void* user_from, size_t n);

// Copies data from kernel space to user space.
// Returns 0 on success, -EFAULT on failure.
NODISCARD int copy_to_user(void* user_to, const void* from, size_t n);

// Zeroes a block of memory in user space.
// Returns 0 on success, -EFAULT on failure.
NODISCARD int clear_user(void* user_to, size_t n);

// Gets the length of a string in user space.
// Returns the shorter of the string length and n, or -EFAULT on failure.
NODISCARD ssize_t strnlen_user(const char* user_str, size_t n);

// Copies a string from user space to kernel space.
// If the string is shorter than n, the rest of the dest buffer is zeroed.
// Returns the shorter of the string length and n, or -EFAULT on failure.
NODISCARD ssize_t strncpy_from_user(char* dest, const char* user_src, size_t n);

// Copies a pathname from user space to kernel space.
// Ensures the pathname is null-terminated and does not exceed PATH_MAX.
// Returns 0 on success, -ENAMETOOLONG if the pathname is too long,
// or -EFAULT on failure.
NODISCARD ssize_t copy_pathname_from_user(char dest[static PATH_MAX],
                                          const char* user_src);

// Atomic load of a 32-bit value from user space.
// Returns 0 on success, -EINVAL if the pointer is not 4-byte aligned,
// or -EFAULT on failure.
NODISCARD int atomic_load_u32_from_user(const uint32_t* user_ptr,
                                        uint32_t* out);

// Atomically stores a 32-bit value to user space.
// Returns 0 on success, -EINVAL if the pointer is not 4-byte aligned,
// or -EFAULT on failure.
NODISCARD int atomic_store_u32_to_user(uint32_t* user_ptr, uint32_t value);
