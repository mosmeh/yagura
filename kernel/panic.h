#pragma once

#include <common/panic.h>
#include <kernel/api/err.h>

#define ASSERT_OK(result)                                                      \
    __extension__({                                                            \
        __typeof__(result) __result = (result);                                \
        if (IS_ERR(__result))                                                  \
            PANIC("Unexpected error: " #result " = %ld", (long)__result);      \
        __result;                                                              \
    })

#define ASSERT_PTR(ptr)                                                        \
    __extension__({                                                            \
        __typeof__(ptr) __ptr = (ptr);                                         \
        if (IS_ERR_OR_NULL(__ptr))                                             \
            PANIC("Invalid pointer: " #ptr " = %ld", (long)__ptr);             \
        __ptr;                                                                 \
    })
