#include <common/limits.h>
#include <common/stddef.h>
#include <common/stdint.h>

unsigned long long __udivmoddi4(unsigned long long lhs, unsigned long long rhs,
                                unsigned long long* rem) {
    if (lhs <= UINT32_MAX && rhs <= UINT32_MAX) {
        unsigned int q;
        unsigned int r;
        __asm__ volatile("divl %[b]"
                         : "=a"(q), "=d"(r)
                         : "d"(0),
                           "a"((unsigned int)lhs), [b] "rm"((unsigned int)rhs));
        if (rem)
            *rem = r;
        return q;
    }

    unsigned long long q = 0;
    unsigned long long r = 0;
    for (int i = ULLONG_WIDTH - 1; i >= 0; --i) {
        r = (r << 1) | ((lhs >> i) & 1);
        if (r >= rhs) {
            r -= rhs;
            q |= 1ULL << i;
        }
    }
    if (rem)
        *rem = r;
    return q;
}

unsigned long long __udivdi3(unsigned long long lhs, unsigned long long rhs) {
    return __udivmoddi4(lhs, rhs, NULL);
}

unsigned long long __umoddi3(unsigned long long lhs, unsigned long long rhs) {
    unsigned long long rem = 0;
    __udivmoddi4(lhs, rhs, &rem);
    return rem;
}

long long __divmoddi4(long long lhs, long long rhs, long long* rem) {
    if (rhs == 0 || (lhs == LLONG_MIN && rhs == -1)) {
        // Raise #DE
        return __udivmoddi4((unsigned long long)lhs, 0, NULL);
    }

    unsigned long long abs_lhs = (unsigned long long)lhs;
    if (lhs < 0)
        abs_lhs = -lhs;
    unsigned long long abs_rhs = (unsigned long long)rhs;
    if (rhs < 0)
        abs_rhs = -rhs;

    unsigned long long q = __udivdi3(abs_lhs, abs_rhs);
    if (rem) {
        long long r = abs_lhs - q * abs_rhs;
        *rem = lhs < 0 ? -r : r;
    }
    return ((lhs < 0) ^ (rhs < 0)) ? -(long long)q : (long long)q;
}

long long __divdi3(long long lhs, long long rhs) {
    return __divmoddi4(lhs, rhs, NULL);
}

long long __moddi3(long long lhs, long long rhs) {
    long long rem = 0;
    __divmoddi4(lhs, rhs, &rem);
    return rem;
}
