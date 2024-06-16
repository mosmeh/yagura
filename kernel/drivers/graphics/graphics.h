#pragma once

#include <kernel/api/fb.h>
#include <kernel/api/sys/types.h>

struct fb {
    int (*get_info)(struct fb_info* out_info);
    int (*set_info)(struct fb_info* inout_info);
    int (*mmap)(uintptr_t addr, size_t length, off_t offset,
                uint16_t page_flags);
};

struct fb* fb_get(void);
