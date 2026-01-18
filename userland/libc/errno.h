#pragma once

#include <kernel/api/errno.h>

__attribute__((const)) int* __errno_location(void);

#define errno (*__errno_location())
