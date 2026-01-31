#include <common/string.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    int fd = open("/dev/fb0", O_RDWR);
    if (fd < 0) {
        ASSERT(errno == ENOENT);
        return EXIT_SUCCESS;
    }

    struct fb_fix_screeninfo fix;
    ASSERT_OK(ioctl(fd, FBIOGET_FSCREENINFO, &fix));
    struct fb_var_screeninfo var;
    ASSERT_OK(ioctl(fd, FBIOGET_VSCREENINFO, &var));

    void* fb =
        mmap(NULL, fix.smem_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ASSERT_OK(close(fd));
    ASSERT(fb != MAP_FAILED);
    void* buf = malloc(fix.smem_len);
    ASSERT(buf);
    memcpy(buf, fb, fix.smem_len);
    memcpy(fb, buf, fix.smem_len);
    free(buf);
    ASSERT_OK(munmap(fb, fix.smem_len));

    return EXIT_SUCCESS;
}
