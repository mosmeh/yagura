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

#define ASSERT_ERRNO(result, expected_errno)                                   \
    __extension__({                                                            \
        errno = 0;                                                             \
        __typeof__(result) __result = ASSERT_ERR(result);                      \
        if (errno != (expected_errno))                                         \
            PANIC("Unexpected errno: " #result " returned %s, expected %s",    \
                  strerrorname_np(errno), strerrorname_np(expected_errno));    \
        __result;                                                              \
    })

const char* strerrorname_np(int errnum);
