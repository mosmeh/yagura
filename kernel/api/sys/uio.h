#pragma once

#include <common/stddef.h>

struct iovec {
    void* iov_base; // Starting address
    size_t iov_len; // Size of the memory pointed to by iov_base.
};
