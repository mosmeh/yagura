#include <kernel/api/err.h>
#include <kernel/drivers/graphics/graphics.h>
#include <kernel/kmsg.h>
#include <kernel/multiboot.h>

static struct fb_info info;

static int multiboot_fb_get_info(struct fb_info* out_info) {
    *out_info = info;
    return 0;
}

static int multiboot_fb_set_info(struct fb_info* inout_info) {
    (void)inout_info;
    return -ENOTSUP;
}

struct fb* multiboot_fb_init(const multiboot_info_t* mb_info) {
    if (!(mb_info->flags & MULTIBOOT_INFO_FRAMEBUFFER_INFO))
        return NULL;
    if (mb_info->framebuffer_type != MULTIBOOT_FRAMEBUFFER_TYPE_RGB)
        return NULL;

    info = (struct fb_info){
        .id = "multiboot",
        .phys_addr = mb_info->framebuffer_addr,
        .width = mb_info->framebuffer_width,
        .height = mb_info->framebuffer_height,
        .pitch = mb_info->framebuffer_pitch,
        .bpp = mb_info->framebuffer_bpp,
    };
    kprintf("multiboot_fb: found framebuffer at P%#zx\n", info.phys_addr);

    static struct fb fb = {
        .get_info = multiboot_fb_get_info,
        .set_info = multiboot_fb_set_info,
    };
    return &fb;
}
