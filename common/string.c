#include "string.h"
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>

void* memset(void* s, int c, size_t n) {
    uintptr_t dest = (uintptr_t)s;

    bool aligned = !((uintptr_t)s & (alignof(uint32_t) - 1));
    if (aligned && n >= sizeof(uint32_t)) {
        size_t nd = n / sizeof(uint32_t);
        uint32_t d =
            (uint32_t)c << 24 | (uint32_t)c << 16 | (uint32_t)c << 8 | c;
        __asm__ volatile("rep stosl"
                         : "=D"(dest)
                         : "D"(dest), "c"(nd), "a"(d)
                         : "memory");
        n -= sizeof(uint32_t) * nd;
        if (n == 0)
            return s;
    }

    __asm__ volatile("rep stosb"
                     : "=D"(dest), "=c"(n)
                     : "0"(dest), "1"(n), "a"(c)
                     : "memory");
    return s;
}

void* memcpy(void* dest_ptr, const void* src_ptr, size_t n) {
    size_t dest = (size_t)dest_ptr;
    size_t src = (size_t)src_ptr;

    bool aligned = !((uintptr_t)dest_ptr & (alignof(uint32_t) - 1)) &&
                   !((uintptr_t)src_ptr & (alignof(uint32_t) - 1));
    if (aligned && n >= sizeof(uint32_t)) {
        size_t nd = n / sizeof(uint32_t);
        __asm__ volatile("rep movsl"
                         : "=S"(src), "=D"(dest)
                         : "S"(src), "D"(dest), "c"(nd)
                         : "memory");
        n -= sizeof(uint32_t) * nd;
        if (n == 0)
            return dest_ptr;
    }

    __asm__ volatile("rep movsb" ::"S"(src), "D"(dest), "c"(n) : "memory");
    return dest_ptr;
}

int strcmp(const char* s1, const char* s2) {
    while (*s1 && *s2) {
        if (*s1 != *s2)
            return *(const unsigned char*)s1 - *(const unsigned char*)s2;
        s1++;
        s2++;
    }
    return 0;
}

int strncmp(const char* s1, const char* s2, size_t n) {
    if (!n)
        return 0;
    do {
        if (*s1 != *s2++)
            return *(const unsigned char*)s1 - *(const unsigned char*)--s2;
        if (*s1++ == 0)
            break;
    } while (--n);
    return 0;
}

size_t strlen(const char* str) {
    size_t len = 0;
    while (*str++)
        ++len;
    return len;
}

size_t strnlen(const char* str, size_t n) {
    size_t len = 0;
    while (len < n && *str++)
        ++len;
    return len;
}

char* strcpy(char* dest, const char* src) {
    char* d = dest;
    while (*src)
        *d++ = *src++;
    return dest;
}

char* strncpy(char* dest, const char* src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; ++i)
        dest[i] = src[i];
    for (; i < n; ++i)
        dest[i] = '\0';
    return dest;
}

void str_replace_char(char* str, char from, char to) {
    while (*str) {
        if (*str == from) {
            *str++ = to;
        } else {
            ++str;
        }
    }
}
