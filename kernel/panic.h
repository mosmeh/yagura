#pragma once

#include <common/panic.h>
#include <kernel/api/err.h>

#define ASSERT_OK(result) ASSERT(IS_OK(result))
#define ASSERT_PTR(ptr) ASSERT(!IS_ERR_OR_NULL(ptr))
