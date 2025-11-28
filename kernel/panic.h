#pragma once

#include "api/err.h"
#include <common/panic.h>

#define ASSERT_OK(result) ASSERT(IS_OK(result))
#define ASSERT_PTR(ptr) ASSERT(!IS_ERR_OR_NULL(ptr))
