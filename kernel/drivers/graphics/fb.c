#include "graphics.h"
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

static int fb_device_mmap(file_description* desc, uintptr_t addr, size_t length,
                          off_t offset, uint16_t page_flags) {
    (void)desc;
    return fb->mmap(addr, length, offset, page_flags);
}

static int fb_device_ioctl(file_description* desc, int request,
                           void* user_argp) {
    (void)desc;

    struct fb_info info;
    switch (request) {
    case FBIOGET_INFO: {
        int rc = fb->get_info(&info);
        if (IS_ERR(rc))
            return rc;
        break;
    }
    case FBIOSET_INFO: {
        if (!copy_from_user(&info, user_argp, sizeof(struct fb_info)))
            return -EFAULT;
        int rc = fb->set_info(&info);
        if (IS_ERR(rc))
            return rc;
        break;
    }
    default:
        return -EINVAL;
    }

    if (!copy_to_user(user_argp, &info, sizeof(struct fb_info)))
        return -EFAULT;
    return 0;
}

static struct inode* fb_device_get(void) {
    static file_ops fops = {.mmap = fb_device_mmap, .ioctl = fb_device_ioctl};
    static struct inode inode = {
        .fops = &fops, .mode = S_IFBLK, .rdev = makedev(29, 0), .ref_count = 1};
    return &inode;
}

void fb_init(const multiboot_info_t* mb_info) {
    fb = find_fb(mb_info);
    if (!fb)
        return;
    ASSERT_OK(vfs_register_device(fb_device_get()));
}
