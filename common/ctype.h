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
