#pragma once

#include <kernel/forward.h>
#include <stddef.h>

enum { FBIOGET_RESOLUTION, FBIOSET_RESOLUTION };

typedef struct fb_resolution {
    size_t width;
    size_t height;
    size_t pitch;
} fb_resolution;

void bochs_graphics_init(void);
fs_node* bochs_graphics_device_create(void);
