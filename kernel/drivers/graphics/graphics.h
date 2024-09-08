#pragma once

#include <kernel/api/sys/types.h>
#include <stddef.h>

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
    void* (*mmap)(size_t length, off_t offset, int flags);
};

struct fb* fb_get(void);
