#include "stdlib.h"
#include "ctype.h"

int atoi(const char* str) {
    if (!*str)
        return 0;
    while (*str && isspace(*str))
        ++str;
    int res = 0;
    while ('0' <= *str && *str <= '9') {
        res *= 10;
        res += *str++ - '0';
    }
    return res;
}
