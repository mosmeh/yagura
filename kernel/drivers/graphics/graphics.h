#pragma once

#include <stddef.h>
#include <stdint.h>

struct fb_info {
    char id[16];
    uintptr_t phys_addr;
    size_t width;
    size_t height;
    size_t pitch;
    size_t bpp;
};

struct fb {
    int (*get_info)(struct fb_info* out_info);
    int (*set_info)(struct fb_info* inout_info);
};

struct fb* fb_get(void);
void* fb_get_buf(void);
