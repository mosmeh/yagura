#include <errno.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    rmdir("/tmp/test-mount");
    ASSERT_OK(mkdir("/tmp/test-mount", 0755));

    errno = 0;
    ASSERT_ERR(mount(NULL, "/tmp/test-mount", NULL, 0, NULL));
    ASSERT(errno == EINVAL);

    errno = 0;
    ASSERT_ERR(mount(NULL, NULL, "type", 0, NULL));
    ASSERT(errno == EFAULT);

    errno = 0;
    ASSERT_ERR(mount((void*)1, NULL, "tmpfs", 0, NULL));
    ASSERT(errno == EFAULT);

    errno = 0;
    ASSERT_ERR(mount(NULL, "/tmp/test-mount", "no-such-fs", 0, NULL));
    ASSERT(errno == ENODEV);

    errno = 0;
    ASSERT_ERR(mount((void*)1, "/tmp/test-mount", "no-such-fs", 0, NULL));
    ASSERT(errno == EFAULT);

    errno = 0;
    ASSERT_ERR(mount(NULL, "no-such-dir", "tmpfs", 0, NULL));
    ASSERT(errno == ENOENT);

    errno = 0;
    ASSERT_OK(mount(NULL, "/tmp/test-mount", "tmpfs", 0, NULL));

    ASSERT_OK(mkdir("/tmp/test-mount/subdir", 0755));
    ASSERT_OK(access("/tmp/test-mount/subdir", F_OK));

    return EXIT_SUCCESS;
}
