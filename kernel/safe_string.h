#pragma once

#include "api/sys/types.h"
#include <common/extra.h>

struct registers;

NODISCARD bool safe_memcpy(void* dest, const void* src, size_t n);
NODISCARD bool safe_memset(void* s, unsigned char c, size_t n);
NODISCARD ssize_t safe_strnlen(const char* str, size_t n);
NODISCARD ssize_t safe_strncpy(char* dest, const char* src, size_t n);

NODISCARD bool copy_from_user(void* to, const void* user_from, size_t n);
NODISCARD bool copy_to_user(void* user_to, const void* from, size_t n);
NODISCARD bool clear_user(void* user_to, size_t n);
NODISCARD ssize_t strnlen_user(const char* user_str, size_t n);
NODISCARD ssize_t strncpy_from_user(char* dest, const char* user_src, size_t n);

NODISCARD bool safe_string_handle_page_fault(struct registers* regs);
