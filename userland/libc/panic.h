#pragma once

#include <common/panic.h>
#include <errno.h>

#define ASSERT_OK(result)                                                      \
    __extension__({                                                            \
        __typeof__(result) __result = (result);                                \
        if (__result < 0)                                                      \
            PANIC("Unexpected error: " #result " = %ld (errno=%s)",            \
                  (long)__result, strerrorname_np(errno));                     \
        __result;                                                              \
    })

#define ASSERT_ERR(result)                                                     \
    __extension__({                                                            \
        __typeof__(result) __result = (result);                                \
        if (__result >= 0)                                                     \
            PANIC("Expected " #result " to fail, but it returned %ld",         \
                  (long)__result);                                             \
        __result;                                                              \
    })

const char* strerrorname_np(int errnum);
