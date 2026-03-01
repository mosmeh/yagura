#include "../io.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <linux/major.h>
#include <panic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

int main(void) {
    unlink("/tmp/dev-fb0");
    ASSERT_OK(mknod("/tmp/dev-fb0", S_IFCHR | 0666, makedev(FB_MAJOR, 0)));

    int fd = open("/tmp/dev-fb0", O_RDWR);
    if (fd < 0) {
        switch (errno) {
        case ENXIO:
        case ENODEV:
        case EACCES:
            return EXIT_SUCCESS;
        default:
            PANIC("Unexpected error: %d", errno);
        }
    }

    struct fb_fix_screeninfo fix;
    ASSERT_OK(ioctl(fd, FBIOGET_FSCREENINFO, &fix));
    struct fb_var_screeninfo var;
    ASSERT_OK(ioctl(fd, FBIOGET_VSCREENINFO, &var));

    char x;
    ASSERT_OK(read_exact(fd, &x, 1));
    ASSERT(lseek(fd, 0, SEEK_END) == 0);
    ASSERT(lseek(fd, 0, SEEK_SET) == 0);
    ASSERT_OK(write_all(fd, &x, 1));
    ASSERT(lseek(fd, 0, SEEK_CUR) == 1);

    void* fb =
        mmap(NULL, fix.smem_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ASSERT_OK(close(fd));
    ASSERT(fb != MAP_FAILED);
    void* buf = ASSERT(malloc(fix.smem_len));
    memcpy(buf, fb, fix.smem_len);
    memcpy(fb, buf, fix.smem_len);
    free(buf);
    ASSERT_OK(munmap(fb, fix.smem_len));

    return EXIT_SUCCESS;
}
