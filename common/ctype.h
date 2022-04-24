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

static inline int isprint(int c) { return 0x20 <= c && c <= 0x7e; }
