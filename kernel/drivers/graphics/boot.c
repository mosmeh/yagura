#include <kernel/api/err.h>
#include <kernel/arch/system.h>
#include <kernel/kmsg.h>

static int boot_fb_get_info(struct fb_info* out_info) {
    *out_info = boot_params.fb_info;
    return 0;
}

static int boot_fb_set_info(struct fb_info* inout_info) {
    (void)inout_info;
    return -ENOTSUP;
}

struct fb* boot_fb_init(void) {
    if (!boot_params.fb_info.phys_addr)
        return NULL;

    kprintf("boot_fb: found framebuffer at P%#zx\n",
            boot_params.fb_info.phys_addr);

    static struct fb fb = {
        .get_info = boot_fb_get_info,
        .set_info = boot_fb_set_info,
    };
    return &fb;
}
