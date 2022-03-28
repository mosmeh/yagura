#pragma once

#include "types.h"
#include <stddef.h>

typedef struct dirent {
    uint32_t type;
    ino_t ino;
    size_t record_len;
    char name[];
} dirent;
