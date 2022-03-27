#pragma once

#include <kernel/forward.h>
#include <stddef.h>

enum { FBIOGET_INFO, FBIOSET_INFO };

typedef struct fb_info {
    size_t width;
    size_t height;
    size_t pitch;
    size_t bpp;
} fb_info;

void bochs_graphics_init(void);
fs_node* bochs_graphics_device_create(void);
