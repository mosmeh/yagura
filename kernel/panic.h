#pragma once

#include "api/err.h"
#include <common/panic.h>

#define ASSERT_OK(result) ASSERT(IS_OK(result))
