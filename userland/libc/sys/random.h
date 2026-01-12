#pragma once

#include <common/stddef.h>
#include <kernel/api/sys/types.h>

ssize_t getrandom(void* buf, size_t buflen, unsigned int flags);
