#pragma once

#include <stdint.h>

typedef struct initrd_header {
    uint32_t num_files;
} initrd_header;

typedef struct initrd_file_header {
    char name[128];
    uint32_t offset;
    uint32_t length;
} initrd_file_header;
