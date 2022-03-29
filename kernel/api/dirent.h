#pragma once

#include "types.h"
#include <stddef.h>

#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12
#define DT_WHT 14

typedef struct dirent {
    size_t record_len;
    uint8_t type;
    char name[];
} dirent;
