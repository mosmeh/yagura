#include "fb_private.h"
#include "graphics.h"
#include <kernel/api/err.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/memory/memory.h>
#include <kernel/safe_string.h>
#include <stddef.h>

static struct fb* fb;

bool fb_init(const multiboot_info_t* mb_info) {
    fb = bochs_fb_init();
    if (fb)
        return true;
    fb = multiboot_fb_init(mb_info);
    return fb;
}

int fb_get_info(struct fb_info* out_info) { return fb->get_info(out_info); }

int fb_set_info(struct fb_info* inout_info) { return fb->set_info(inout_info); }

int fb_mmap(uintptr_t addr, size_t length, off_t offset, uint16_t page_flags) {
    return fb->mmap(addr, length, offset, page_flags);
}

static int fb_device_mmap(file_description* desc, uintptr_t addr, size_t length,
                          off_t offset, uint16_t page_flags) {
    (void)desc;
    return fb_mmap(addr, length, offset, page_flags);
}

static int fb_device_ioctl(file_description* desc, int request,
                           void* user_argp) {
    (void)desc;

    struct fb_info info;
    switch (request) {
    case FBIOGET_INFO: {
        int rc = fb_get_info(&info);
        if (IS_ERR(rc))
            return rc;
        break;
    }
    case FBIOSET_INFO: {
        if (!copy_from_user(&info, user_argp, sizeof(struct fb_info)))
            return -EFAULT;
        int rc = fb_set_info(&info);
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

struct inode* fb_device_create(void) {
    struct inode* inode = kmalloc(sizeof(struct inode));
    if (!inode)
        return ERR_PTR(-ENOMEM);

    static file_ops fops = {.mmap = fb_device_mmap, .ioctl = fb_device_ioctl};
    *inode = (struct inode){.fops = &fops,
                            .mode = S_IFBLK,
                            .device_id = makedev(29, 0),
                            .ref_count = 1};
    return inode;
}
