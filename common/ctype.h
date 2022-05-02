#pragma once

static inline int isspace(int c) {
    switch (c) {
    case '\t':
    case '\n':
    case '\v':
    case '\f':
    case '\r':
    case ' ':
        return 1;
    }
    return 0;
}

static inline int isprint(int c) { return (int)(0x20 <= c && c <= 0x7e); }

static inline int tolower(int c) {
    if ('A' <= c && c <= 'Z')
        return c | 0x20;
    return c;
}

static inline int toupper(int c) {
    if ('a' <= c && c <= 'z')
        return c & ~0x20;
    return c;
}
