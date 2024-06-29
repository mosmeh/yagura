#pragma once

#include <kernel/api/fb.h>
#include <kernel/api/sys/types.h>

struct fb {
    int (*get_info)(struct fb_info* out_info);
    int (*set_info)(struct fb_info* inout_info);
    void* (*mmap)(size_t length, off_t offset, int flags);
};

struct fb* fb_get(void);
