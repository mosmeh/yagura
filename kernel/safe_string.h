#pragma once

#include <common/extra.h>
#include <kernel/api/sys/types.h>

struct registers;

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

NODISCARD bool safe_string_handle_page_fault(struct registers* regs);
