#include "../io.h"
#include <fcntl.h>
#include <linux/major.h>
#include <panic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

int main(void) {
    char buf[16] = {0};
    {
        unlink("/tmp/dev-null");
        ASSERT_OK(
            mknod("/tmp/dev-null", S_IFCHR | 0666, makedev(MEM_MAJOR, 3)));
        int fd = ASSERT_OK(open("/tmp/dev-null", O_RDWR));
        ASSERT(read_to_end(fd, buf, sizeof(buf)) == 0);
        ASSERT_OK(write_all(fd, buf, sizeof(buf)));
        ASSERT(lseek(fd, 12345, SEEK_SET) == 0);
        ASSERT_OK(close(fd));
    }
    {
        unlink("/tmp/dev-zero");
        ASSERT_OK(
            mknod("/tmp/dev-zero", S_IFCHR | 0666, makedev(MEM_MAJOR, 5)));
        int fd = ASSERT_OK(open("/tmp/dev-zero", O_RDWR));
        memset(buf, 0xff, sizeof(buf));
        ASSERT_OK(read_exact(fd, buf, sizeof(buf)));
        for (size_t i = 0; i < sizeof(buf); ++i)
            ASSERT(buf[i] == 0);
        ASSERT_OK(write_all(fd, buf, sizeof(buf)));
        ASSERT(lseek(fd, 12345, SEEK_SET) == 0);
        ASSERT_OK(close(fd));
    }
    {
        unlink("/tmp/dev-full");
        ASSERT_OK(
            mknod("/tmp/dev-full", S_IFCHR | 0666, makedev(MEM_MAJOR, 7)));
        int fd = ASSERT_OK(open("/tmp/dev-full", O_RDWR));
        memset(buf, 0xff, sizeof(buf));
        ASSERT_OK(read_exact(fd, buf, sizeof(buf)));
        for (size_t i = 0; i < sizeof(buf); ++i)
            ASSERT(buf[i] == 0);
        ASSERT_ERRNO(write_all(fd, buf, sizeof(buf)), ENOSPC);
        ASSERT(lseek(fd, 12345, SEEK_SET) == 0);
        ASSERT_OK(close(fd));
    }
    return EXIT_SUCCESS;
}
