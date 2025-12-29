#pragma once

#include <kernel/api/sys/types.h>
#include <stddef.h>

ssize_t getrandom(void* buf, size_t buflen, unsigned int flags);
