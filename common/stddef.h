#pragma once

#define NULL ((void*)0)

typedef __SIZE_TYPE__ size_t;

typedef struct {
    long long __max_align1 __attribute__((__aligned__(__alignof__(long long))));
    long double __max_align2
        __attribute__((__aligned__(__alignof__(long double))));
    void* __max_align3 __attribute__((__aligned__(__alignof__(void*))));
} max_align_t;
