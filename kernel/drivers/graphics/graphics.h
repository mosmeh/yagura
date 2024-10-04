#pragma once

#include <stddef.h>
#include <stdint.h>

struct fb_info {
    char id[16];
    size_t width;
    size_t height;
    size_t pitch;
    size_t bpp;
};

struct fb {
    int (*get_info)(struct fb_info* out_info);
    int (*set_info)(struct fb_info* inout_info);
    void* (*mmap)(size_t length, uint64_t offset, int flags);
};

struct fb* fb_get(void);
