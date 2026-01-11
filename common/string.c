#include <common/string.h>
#include <stdint.h>

void* memmove(void* dest, const void* src, size_t n) {
    if (((uintptr_t)dest - (uintptr_t)src) >= n)
        return memcpy(dest, src, n);

    unsigned char* d = (unsigned char*)dest + n;
    const unsigned char* s = (const unsigned char*)src + n;
    for (; n--;)
        *--d = *--s;
    return dest;
}

int memcmp(const void* s1, const void* s2, size_t n) {
    const unsigned char* c1 = (const unsigned char*)s1;
    const unsigned char* c2 = (const unsigned char*)s2;
    while (n--) {
        if (*c1++ != *c2++)
            return c1[-1] < c2[-1] ? -1 : 1;
    }
    return 0;
}

void* memchr(const void* s, int c, size_t n) {
    const unsigned char* p = s;
    unsigned char uc = (unsigned char)c;
    for (size_t i = 0; i < n; ++i) {
        if (p[i] == uc)
            return (void*)(p + i);
    }
    return NULL;
}

int strcmp(const char* s1, const char* s2) {
    for (; *s1 == *s2; ++s1, ++s2) {
        if (*s1 == 0)
            return 0;
    }
    return *(const unsigned char*)s1 < *(const unsigned char*)s2 ? -1 : 1;
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
    while ((*d++ = *src++))
        ;
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

size_t strlcpy(char* dst, const char* src, size_t size) {
    size_t len;
    for (len = 0; (len + 1 < size) && *src; len++)
        *dst++ = *src++;
    if (size > 0)
        *dst = '\0';
    while (*src++)
        len++;
    return len;
}

char* strcat(char* dest, const char* src) {
    size_t dest_len = strlen(dest);
    size_t i = 0;
    for (; src[i]; ++i)
        dest[dest_len + i] = src[i];
    dest[dest_len + i] = 0;
    return dest;
}

char* strncat(char* dest, const char* src, size_t n) {
    size_t dest_len = strlen(dest);
    size_t i = 0;
    for (; i < n && src[i]; ++i)
        dest[dest_len + i] = src[i];
    dest[dest_len + i] = 0;
    return dest;
}

char* strchr(const char* str, int ch) {
    while (*str) {
        if (*str == ch)
            return (char*)str;
        ++str;
    }
    return NULL;
}

char* strnchr(const char* str, size_t n, int ch) {
    for (size_t i = 0; i < n && *str; ++i) {
        if (*str == ch)
            return (char*)str;
        ++str;
    }
    return NULL;
}

char* strrchr(const char* str, int ch) {
    char* last = NULL;
    while (*str) {
        if (*str == ch)
            last = (char*)str;
        ++str;
    }
    return last;
}

char* strtok(char* str, const char* sep) {
    static char* saved_ptr;
    return strtok_r(str, sep, &saved_ptr);
}

char* strtok_r(char* str, const char* sep, char** last) {
    if (!str) {
        if (!*last)
            return NULL;
        str = *last;
    }

    while (*str) {
        if (!strchr(sep, *str))
            break;
        ++str;
    }
    if (!*str) {
        *last = NULL;
        return NULL;
    }

    char* end = str;
    while (*end) {
        if (strchr(sep, *end))
            break;
        ++end;
    }
    if (*end)
        *last = end + 1;
    else
        *last = NULL;
    *end = '\0';
    return str;
}

char* strstr(const char* str, const char* substr) {
    size_t len = strlen(substr);
    while (*str) {
        if (!strncmp(str, substr, len))
            return (char*)str;
        ++str;
    }
    return NULL;
}
