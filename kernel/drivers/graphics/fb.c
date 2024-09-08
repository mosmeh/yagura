#include "graphics.h"
#include <common/string.h>
#include <kernel/api/linux/fb.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>

static struct fb* fb;

struct fb* bochs_fb_init(void);
struct fb* multiboot_fb_init(const multiboot_info_t*);

static struct fb* find_fb(const multiboot_info_t* mb_info) {
    struct fb* fb = bochs_fb_init();
    if (fb)
        return fb;
    return multiboot_fb_init(mb_info);
}

struct fb* fb_get(void) { return fb; }

static void* fb_device_mmap(struct file* file, size_t length, off_t offset,
                            int flags) {
    (void)file;
    return fb->mmap(length, offset, flags);
}

static int fb_device_ioctl(struct file* file, int request, void* user_argp) {
    (void)file;

    switch (request) {
    case FBIOGET_FSCREENINFO: {
        struct fb_info info;
        int rc = fb->get_info(&info);
        if (IS_ERR(rc))
            return rc;
        struct fb_fix_screeninfo fix = {
            .smem_len = info.pitch * info.height,
            .type = FB_TYPE_PACKED_PIXELS,
            .visual = FB_VISUAL_TRUECOLOR,
            .line_length = info.pitch,
        };
        strlcpy(fix.id, info.id, sizeof(fix.id));
        if (copy_to_user(user_argp, &fix, sizeof(struct fb_fix_screeninfo)))
            return -EFAULT;
        return 0;
    }
    case FBIOGET_VSCREENINFO: {
        struct fb_info info;
        int rc = fb->get_info(&info);
        if (IS_ERR(rc))
            return rc;
        struct fb_var_screeninfo var = {
            .xres = info.width,
            .yres = info.height,
            .xres_virtual = info.width,
            .yres_virtual = info.height,
            .bits_per_pixel = info.bpp,
            .red = {.offset = 16, .length = 8},
            .green = {.offset = 8, .length = 8},
            .blue = {.offset = 0, .length = 8},
        };
        if (copy_to_user(user_argp, &var, sizeof(struct fb_var_screeninfo)))
            return -EFAULT;
        return 0;
    }
    case FBIOPUT_VSCREENINFO: {
        struct fb_var_screeninfo var;
        if (copy_from_user(&var, user_argp, sizeof(struct fb_var_screeninfo)))
            return -EFAULT;
        struct fb_info info;
        int rc = fb->get_info(&info);
        if (IS_ERR(rc))
            return rc;
        info.width = var.xres;
        info.height = var.yres;
        info.bpp = var.bits_per_pixel;
        return fb->set_info(&info);
    }
    }

    return -EINVAL;
}

static struct inode* fb_device_get(void) {
    static const struct file_ops fops = {
        .mmap = fb_device_mmap,
        .ioctl = fb_device_ioctl,
    };
    static struct inode inode = {
        .fops = &fops,
        .mode = S_IFBLK,
        .rdev = makedev(29, 0),
        .ref_count = 1,
    };
    return &inode;
}

void fb_init(const multiboot_info_t* mb_info) {
    fb = find_fb(mb_info);
    if (!fb)
        return;
    ASSERT_OK(vfs_register_device("fb0", fb_device_get()));
}
