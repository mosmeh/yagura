#pragma once

#include <kernel/forward.h>
#include <stdbool.h>

bool fb_init(const multiboot_info_t* mb_info);
struct file* fb_device_create(void);
