#include "graphics.h"
#include <kernel/api/err.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/multiboot.h>

static uintptr_t phys_addr;
static struct fb_info info;

static int multiboot_fb_get_info(struct fb_info* out_info) {
    *out_info = info;
    return 0;
}

static int multiboot_fb_set_info(struct fb_info* inout_info) {
    (void)inout_info;
    return -ENOTSUP;
}

static void* multiboot_fb_mmap(size_t length, uint64_t offset, int flags) {
    if (offset != 0)
        return ERR_PTR(-ENXIO);
    if (!(flags & VM_SHARED))
        return ERR_PTR(-ENODEV);

    return vm_phys_map(phys_addr, length, flags | VM_WC);
}

struct fb* multiboot_fb_init(const multiboot_info_t* mb_info) {
    if (!(mb_info->flags & MULTIBOOT_INFO_FRAMEBUFFER_INFO))
        return NULL;
    if (mb_info->framebuffer_type != MULTIBOOT_FRAMEBUFFER_TYPE_RGB)
        return NULL;

    phys_addr = mb_info->framebuffer_addr;
    info = (struct fb_info){
        .id = "multiboot",
        .width = mb_info->framebuffer_width,
        .height = mb_info->framebuffer_height,
        .pitch = mb_info->framebuffer_pitch,
        .bpp = mb_info->framebuffer_bpp,
    };
    kprintf("multiboot_fb: found framebuffer at P%#x\n", phys_addr);

    static struct fb fb = {
        .get_info = multiboot_fb_get_info,
        .set_info = multiboot_fb_set_info,
        .mmap = multiboot_fb_mmap,
    };
    return &fb;
}
