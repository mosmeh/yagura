#include <common/integer.h>
#include <common/string.h>
#include <kernel/api/linux/fb.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/device/device.h>
#include <kernel/drivers/graphics/graphics.h>
#include <kernel/fs/file.h>
#include <kernel/kmsg.h>
#include <kernel/lock/mutex.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/safe_string.h>
#include <kernel/panic.h>

static struct {
    struct fb* backend;
    struct fb_info info;
    struct vm_obj* vm_obj;
    unsigned char* data;
    struct mutex lock;
} fb;

#define BUF_SIZE (fb.info.pitch * fb.info.height)

struct fb* bochs_fb_init(void);
struct fb* boot_fb_init(void);

static struct fb* find_backend(void) {
    static struct fb* (*const candidates[])(void) = {
        bochs_fb_init,
        boot_fb_init,
    };
    for (size_t i = 0; i < ARRAY_SIZE(candidates); ++i) {
        struct fb* backend = candidates[i]();
        if (backend)
            return backend;
    }
    return NULL;
}

struct fb* fb_get(void) { return fb.backend; }

struct vm_obj* fb_mmap(void) {
    SCOPED_LOCK(mutex, &fb.lock);

    if (fb.vm_obj)
        return vm_obj_ref(fb.vm_obj);

    struct vm_obj* vm_obj =
        ASSERT(phys_create(fb.info.phys_addr, DIV_CEIL(BUF_SIZE, PAGE_SIZE)));
    if (IS_ERR(vm_obj))
        return vm_obj;
    vm_obj->flags |= VM_IO | VM_WC;
    fb.vm_obj = vm_obj;

    return vm_obj_ref(vm_obj);
}

NODISCARD static void* map(void) {
    ASSERT(mutex_is_locked_by_current(&fb.lock));

    if (fb.data)
        return fb.data;

    struct vm_obj* vm_obj FREE(vm_obj) = ASSERT(fb_mmap());
    if (IS_ERR(vm_obj))
        return vm_obj;
    void* data = ASSERT(vm_obj_map(vm_obj, 0, DIV_CEIL(BUF_SIZE, PAGE_SIZE),
                                   VM_READ | VM_WRITE | VM_SHARED));
    if (IS_ERR(data))
        return data;
    fb.data = data;
    return data;
}

static ssize_t fb_device_pread(struct file* file, void* user_buffer,
                               size_t count, uint64_t offset) {
    (void)file;
    SCOPED_LOCK(mutex, &fb.lock);

    if (offset >= BUF_SIZE)
        return 0;

    unsigned char* data = ASSERT(map());
    if (IS_ERR(data))
        return PTR_ERR(data);

    count = MIN(count, BUF_SIZE - offset);
    if (copy_to_user(user_buffer, data + offset, count))
        return -EFAULT;
    return count;
}

static ssize_t fb_device_pwrite(struct file* file, const void* user_buffer,
                                size_t count, uint64_t offset) {
    (void)file;
    SCOPED_LOCK(mutex, &fb.lock);

    if (offset >= BUF_SIZE)
        return -ENOSPC;

    unsigned char* data = ASSERT(map());
    if (IS_ERR(data))
        return PTR_ERR(data);

    count = MIN(count, BUF_SIZE - offset);
    if (copy_from_user(data + offset, user_buffer, count))
        return -EFAULT;
    return count;
}

static int fb_device_ioctl(struct file* file, unsigned cmd, unsigned long arg) {
    (void)file;

    switch (cmd) {
    case FBIOGET_FSCREENINFO: {
        struct fb_fix_screeninfo fix;
        {
            SCOPED_LOCK(mutex, &fb.lock);
            fix = (struct fb_fix_screeninfo){
                .smem_len = BUF_SIZE,
                .type = FB_TYPE_PACKED_PIXELS,
                .visual = FB_VISUAL_TRUECOLOR,
                .line_length = fb.info.pitch,
            };
            strlcpy(fix.id, fb.info.id, sizeof(fix.id));
        }
        if (copy_to_user((void*)arg, &fix, sizeof(struct fb_fix_screeninfo)))
            return -EFAULT;
        return 0;
    }
    case FBIOGET_VSCREENINFO: {
        struct fb_var_screeninfo var;
        {
            SCOPED_LOCK(mutex, &fb.lock);
            var = (struct fb_var_screeninfo){
                .xres = fb.info.width,
                .yres = fb.info.height,
                .xres_virtual = fb.info.width,
                .yres_virtual = fb.info.height,
                .bits_per_pixel = fb.info.bpp,
                .red = {.offset = 16, .length = 8},
                .green = {.offset = 8, .length = 8},
                .blue = {.offset = 0, .length = 8},
            };
        }
        if (copy_to_user((void*)arg, &var, sizeof(struct fb_var_screeninfo)))
            return -EFAULT;
        return 0;
    }
    case FBIOPUT_VSCREENINFO: {
        struct fb_var_screeninfo var;
        if (copy_from_user(&var, (const void*)arg,
                           sizeof(struct fb_var_screeninfo)))
            return -EFAULT;

        SCOPED_LOCK(mutex, &fb.lock);

        struct fb_info new_info = fb.info;
        new_info.width = var.xres;
        new_info.height = var.yres;
        new_info.bpp = var.bits_per_pixel;

        int rc = fb.backend->set_info(&new_info);
        if (IS_ERR(rc))
            return rc;

        fb.info = new_info;
        // Unmap the old framebuffer as the physical address or size may
        // have changed.
        vm_obj_unref(fb.vm_obj);
        fb.vm_obj = NULL;
        vm_obj_unmap(fb.data);
        fb.data = NULL;
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
    struct fb* backend = find_backend();
    if (!backend)
        return;

    int rc = backend->get_info(&fb.info);
    if (IS_ERR(rc)) {
        kprintf("fb: failed to get fb info: %d\n", rc);
        return;
    }

    static const struct file_ops fops = {
        .pread = fb_device_pread,
        .pwrite = fb_device_pwrite,
        .seek = default_file_seek,
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
    fb.backend = backend;
}
