#pragma once

#include <common/panic.h>

#define ASSERT_OK(result) ASSERT((result) >= 0)
#define ASSERT_ERR(result) ASSERT((result) < 0)
