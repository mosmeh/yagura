#include <common/integer.h>
#include <common/string.h>
#include <kernel/api/linux/fb.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/device/device.h>
#include <kernel/drivers/graphics/graphics.h>
#include <kernel/fs/file.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/safe_string.h>
#include <kernel/panic.h>

static struct fb* fb;
static struct fb_info fb_info;
static struct vm_obj* vm_obj;

struct fb* bochs_fb_init(void);
struct fb* boot_fb_init(void);

static struct fb* find_fb(void) {
    static struct fb* (*const candidates[])(void) = {
        bochs_fb_init,
        boot_fb_init,
    };
    for (size_t i = 0; i < ARRAY_SIZE(candidates); ++i) {
        struct fb* found_fb = candidates[i]();
        if (found_fb)
            return found_fb;
    }
    return NULL;
}

struct fb* fb_get(void) { return fb; }

struct vm_obj* fb_mmap(void) { return vm_obj_ref(vm_obj); }

static size_t buf_size(void) { return fb_info.pitch * fb_info.height; }

static int fb_device_ioctl(struct file* file, unsigned cmd, unsigned long arg) {
    (void)file;

    switch (cmd) {
    case FBIOGET_FSCREENINFO: {
        struct fb_fix_screeninfo fix = {
            .smem_len = buf_size(),
            .type = FB_TYPE_PACKED_PIXELS,
            .visual = FB_VISUAL_TRUECOLOR,
            .line_length = fb_info.pitch,
        };
        strlcpy(fix.id, fb_info.id, sizeof(fix.id));
        if (copy_to_user((void*)arg, &fix, sizeof(struct fb_fix_screeninfo)))
            return -EFAULT;
        return 0;
    }
    case FBIOGET_VSCREENINFO: {
        struct fb_var_screeninfo var = {
            .xres = fb_info.width,
            .yres = fb_info.height,
            .xres_virtual = fb_info.width,
            .yres_virtual = fb_info.height,
            .bits_per_pixel = fb_info.bpp,
            .red = {.offset = 16, .length = 8},
            .green = {.offset = 8, .length = 8},
            .blue = {.offset = 0, .length = 8},
        };
        if (copy_to_user((void*)arg, &var, sizeof(struct fb_var_screeninfo)))
            return -EFAULT;
        return 0;
    }
    case FBIOPUT_VSCREENINFO: {
        struct fb_var_screeninfo var;
        if (copy_from_user(&var, (const void*)arg,
                           sizeof(struct fb_var_screeninfo)))
            return -EFAULT;
        struct fb_info new_info = fb_info;
        new_info.width = var.xres;
        new_info.height = var.yres;
        new_info.bpp = var.bits_per_pixel;
        int rc = fb->set_info(&new_info);
        if (IS_ERR(rc))
            return rc;
        fb_info = new_info;
        return 0;
    }
    }

    return -EINVAL;
}

static struct vm_obj* fb_device_mmap(struct file* file) {
    (void)file;
    return fb_mmap();
}

void fb_init(void) {
    struct fb* found_fb = find_fb();
    if (!found_fb)
        return;

    int rc = found_fb->get_info(&fb_info);
    if (IS_ERR(rc)) {
        kprintf("fb: failed to get fb info: %d\n", rc);
        return;
    }
    vm_obj = phys_create(fb_info.phys_addr, DIV_CEIL(buf_size(), PAGE_SIZE));
    if (IS_ERR(ASSERT(vm_obj))) {
        kprint("fb: failed to create vm object for framebuffer\n");
        return;
    }
    vm_obj->flags |= VM_WC;

    static const struct file_ops fops = {
        .ioctl = fb_device_ioctl,
        .mmap = fb_device_mmap,
    };
    static struct char_dev char_dev = {
        .name = "fb0",
        .dev = makedev(FB_MAJOR, 0),
        .fops = &fops,
    };
    ASSERT_OK(char_dev_register(&char_dev));

    // Expose the framebuffer only if everything is successful.
    fb = found_fb;
}
