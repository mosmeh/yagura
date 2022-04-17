#include <kernel/api/err.h>
#include <kernel/api/fb.h>
#include <kernel/api/stat.h>
#include <kernel/api/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/kmalloc.h>
#include <kernel/kprintf.h>
#include <kernel/mem.h>
#include <kernel/multiboot.h>
#include <stdbool.h>
#include <string.h>

static uintptr_t fb_paddr;
static struct fb_info fb_info;

bool multiboot_fb_init(const multiboot_info_t* mb_info) {
    if (!(mb_info->flags & MULTIBOOT_INFO_FRAMEBUFFER_INFO))
        return false;
    if (mb_info->framebuffer_type != MULTIBOOT_FRAMEBUFFER_TYPE_RGB)
        return false;

    fb_paddr = mb_info->framebuffer_addr;
    fb_info.width = mb_info->framebuffer_width;
    fb_info.height = mb_info->framebuffer_height;
    fb_info.pitch = mb_info->framebuffer_pitch;
    fb_info.bpp = mb_info->framebuffer_bpp;
    kprintf("Found framebuffer at P0x%x\n", fb_paddr);
    return true;
}

static uintptr_t multiboot_fb_device_mmap(file_description* desc,
                                          uintptr_t addr, size_t length,
                                          int prot, off_t offset, bool shared) {
    (void)desc;
    if (offset != 0)
        return -ENXIO;
    if (!shared)
        return -ENODEV;

    int rc = mem_map_to_physical_range(
        addr, fb_paddr, length, mem_prot_to_map_flags(prot) | MEM_SHARED);
    if (IS_ERR(rc))
        return rc;
    return addr;
}

static int multiboot_fb_device_ioctl(file_description* desc, int request,
                                     void* argp) {
    (void)desc;
    switch (request) {
    case FBIOGET_INFO:
        *(struct fb_info*)argp = fb_info;
        return 0;
    case FBIOSET_INFO:
        return -ENOTSUP;
    }
    return -EINVAL;
}

struct file* multiboot_fb_device_create(void) {
    struct file* file = kmalloc(sizeof(struct file));
    if (!file)
        return ERR_PTR(-ENOMEM);
    memset(file, 0, sizeof(struct file));

    file->name = kstrdup("multiboot_fb_device");
    if (!file->name)
        return ERR_PTR(-ENOMEM);

    file->mode = S_IFBLK;
    file->mmap = multiboot_fb_device_mmap;
    file->ioctl = multiboot_fb_device_ioctl;
    file->device_id = makedev(29, 0);
    return file;
}