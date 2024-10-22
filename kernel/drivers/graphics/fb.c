#include "graphics.h"
#include <common/string.h>
#include <kernel/api/linux/fb.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>

static struct fb* fb;
static struct fb_info fb_info;
static unsigned char* fb_buf;

struct fb* bochs_fb_init(void);
struct fb* multiboot_fb_init(const multiboot_info_t*);

static struct fb* find_fb(const multiboot_info_t* mb_info) {
    struct fb* fb = bochs_fb_init();
    if (fb)
        return fb;
    return multiboot_fb_init(mb_info);
}

struct fb* fb_get(void) { return fb; }

void* fb_get_buf(void) {
    ASSERT(fb_buf);
    return fb_buf;
}

static size_t buf_size(void) { return fb_info.pitch * fb_info.height; }

static ssize_t fb_device_pread(struct file* file, void* buffer, size_t count,
                               uint64_t offset) {
    (void)file;
    size_t size = buf_size();
    if (offset >= size)
        return 0;
    count = MIN(count, size - offset);
    memcpy(buffer, fb_buf + offset, count);
    return count;
}

static ssize_t fb_device_pwrite(struct file* file, const void* buffer,
                                size_t count, uint64_t offset) {
    (void)file;
    size_t size = buf_size();
    if (offset >= size)
        return 0;
    count = MIN(count, size - offset);
    memcpy(fb_buf + offset, buffer, count);
    return count;
}

static int fb_device_ioctl(struct file* file, int request, void* user_argp) {
    (void)file;

    switch (request) {
    case FBIOGET_FSCREENINFO: {
        struct fb_fix_screeninfo fix = {
            .smem_len = buf_size(),
            .type = FB_TYPE_PACKED_PIXELS,
            .visual = FB_VISUAL_TRUECOLOR,
            .line_length = fb_info.pitch,
        };
        strlcpy(fix.id, fb_info.id, sizeof(fix.id));
        if (copy_to_user(user_argp, &fix, sizeof(struct fb_fix_screeninfo)))
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
        if (copy_to_user(user_argp, &var, sizeof(struct fb_var_screeninfo)))
            return -EFAULT;
        return 0;
    }
    case FBIOPUT_VSCREENINFO: {
        struct fb_var_screeninfo var;
        if (copy_from_user(&var, user_argp, sizeof(struct fb_var_screeninfo)))
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

static struct inode* fb_device_get(void) {
    static const struct file_ops fops = {
        .pread = fb_device_pread,
        .pwrite = fb_device_pwrite,
        .ioctl = fb_device_ioctl,
    };
    static struct inode inode = {
        .vm_obj = INODE_VM_OBJ_CONST_INIT,
        .fops = &fops,
        .mode = S_IFBLK,
        .rdev = makedev(29, 0),
    };
    return &inode;
}

void fb_init(const multiboot_info_t* mb_info) {
    struct fb* f = find_fb(mb_info);
    if (!f)
        return;

    int rc = f->get_info(&fb_info);
    if (IS_ERR(rc)) {
        kprintf("fb: failed to get fb info: %d\n", rc);
        return;
    }
    fb_buf =
        phys_map(fb_info.phys_addr, buf_size(), VM_READ | VM_WRITE | VM_WC);
    if (!fb_buf) {
        kprint("fb: failed to map framebuffer\n");
        return;
    }

    ASSERT_OK(vfs_register_device("fb0", fb_device_get()));

    fb = f;
}
