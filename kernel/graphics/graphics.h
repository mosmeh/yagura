#pragma once

#include <common/extra.h>
#include <kernel/api/fb.h>
#include <kernel/api/sys/types.h>
#include <kernel/forward.h>
#include <stdbool.h>

NODISCARD bool fb_init(const multiboot_info_t* mb_info);
NODISCARD int fb_get_info(struct fb_info*);
NODISCARD int fb_set_info(struct fb_info*);
NODISCARD int fb_mmap(uintptr_t addr, size_t length, off_t offset,
                      uint16_t page_flags);

struct inode* fb_device_get(void);
