#include "string.h"
#include <stdalign.h>
#include <stdbool.h>

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

static void itoa(int value, char* str, int radix) {
    char* c = str;
    unsigned uvalue = value;

    if (radix == 10 && value < 0) {
        *c++ = '-';
        str++;
        uvalue = -value;
    }

    do {
        int mod = uvalue % radix;
        *c++ = (mod < 10) ? mod + '0' : mod - 10 + 'a';
    } while (uvalue /= radix);

    *c = 0;

    char* p1 = str;
    char* p2 = c - 1;
    while (p1 < p2) {
        char tmp = *p1;
        *p1 = *p2;
        *p2 = tmp;
        p1++;
        p2--;
    }
}

int vsnprintf(char* ret, size_t size, const char* format, va_list args) {
    size_t idx = 0;
    char ch;
    while ((ch = *format++) != 0) {
        if (ch != '%') {
            ret[idx++] = ch;
            if (idx >= size)
                goto too_long;
            continue;
        }

        bool pad0 = false;
        size_t pad_len = 0;

        ch = *format++;
        if (ch == '0') {
            pad0 = true;
            ch = *format++;
        }
        if ('0' <= ch && ch <= '9') {
            pad_len = ch - '0';
            ch = *format++;
        }

        switch (ch) {
        case 'd':
        case 'u':
        case 'x': {
            char buf[20];
            itoa(va_arg(args, int), buf, ch == 'x' ? 16 : 10);

            size_t len = strlen(buf);
            if (pad_len > len) {
                for (size_t i = 0; i < pad_len - len; ++i) {
                    ret[idx++] = pad0 ? '0' : ' ';
                    if (idx >= size)
                        goto too_long;
                }
            }
            for (size_t i = 0; i < len; ++i) {
                ret[idx++] = buf[i];
                if (idx >= size)
                    goto too_long;
            }

            break;
        }
        case 's': {
            const char* str = va_arg(args, const char*);
            if (!str)
                str = "(null)";
            while (*str) {
                ret[idx++] = *str++;
                if (idx >= size)
                    goto too_long;
            }
            break;
        }
        default:
            ret[idx++] = '?';
            if (idx >= size)
                goto too_long;
            break;
        }
    }

too_long:
    ret[idx < size ? idx : size - 1] = '\0';
    return idx;
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
