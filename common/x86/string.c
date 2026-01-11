#include <common/string.h>

// The following functions are implemented using inline assembly to prevent
// infinite recursion caused by compiler optimizations that may replace
// loops with calls to these functions themselves.

void* memset(void* s, int c, size_t n) {
    void* d = s;
    __asm__ volatile("rep stosb"
                     : "=D"(d), "=c"(n)
                     : "0"(s), "1"(n), "a"(c)
                     : "memory");
    return s;
}

void* memcpy(void* dest, const void* src, size_t n) {
    void* d = dest;
    __asm__ volatile("rep movsb"
                     : "=S"(src), "=D"(d), "=c"(n)
                     : "0"(src), "1"(dest), "2"(n)
                     : "memory");
    return dest;
}
