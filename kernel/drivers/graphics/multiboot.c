#include "graphics.h"
#include <kernel/api/err.h>
#include <kernel/kprintf.h>
#include <kernel/memory/memory.h>
#include <kernel/multiboot.h>

static uintptr_t paddr;
static struct fb_info info;

static int multiboot_fb_get_info(struct fb_info* out_info) {
    *out_info = info;
    return 0;
}

static int multiboot_fb_set_info(struct fb_info* inout_info) {
    (void)inout_info;
    return -ENOTSUP;
}

static int multiboot_fb_mmap(uintptr_t addr, size_t length, off_t offset,
                             uint16_t page_flags) {
    if (offset != 0)
        return -ENXIO;
    if (!(page_flags & PAGE_SHARED))
        return -ENODEV;

    return paging_map_to_physical_range(addr, paddr, length,
                                        page_flags | PAGE_PAT);
}

struct fb* multiboot_fb_init(const multiboot_info_t* mb_info) {
    if (!(mb_info->flags & MULTIBOOT_INFO_FRAMEBUFFER_INFO))
        return NULL;
    if (mb_info->framebuffer_type != MULTIBOOT_FRAMEBUFFER_TYPE_RGB)
        return NULL;

    paddr = mb_info->framebuffer_addr;
    info.width = mb_info->framebuffer_width;
    info.height = mb_info->framebuffer_height;
    info.pitch = mb_info->framebuffer_pitch;
    info.bpp = mb_info->framebuffer_bpp;
    kprintf("Found framebuffer at P0x%x\n", paddr);

    static struct fb fb = {.get_info = multiboot_fb_get_info,
                           .set_info = multiboot_fb_set_info,
                           .mmap = multiboot_fb_mmap};
    return &fb;
}
