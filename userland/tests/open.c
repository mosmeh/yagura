#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    unlink("/tmp/test-open/foo");
    rmdir("/tmp/test-open");

    ASSERT_OK(mkdir("/tmp/test-open", 0755));

    ASSERT_ERRNO(open("/tmp/test-open/foo", 0), ENOENT);

    ASSERT_OK(open("/tmp/test-open/foo", O_CREAT | O_EXCL, 0644));
    ASSERT_OK(open("/tmp/test-open/foo", O_CREAT, 0644));

    ASSERT_ERRNO(open("/tmp/test-open/foo", O_CREAT | O_EXCL, 0644), EEXIST);
    ASSERT_ERRNO(open("/tmp/test-open/foo/bar", 0), ENOTDIR);

    int fd = ASSERT_OK(open("/tmp/test-open/foo", O_RDONLY | O_CLOEXEC));
    int flags = ASSERT_OK(fcntl(fd, F_GETFL));
    ASSERT((flags & O_ACCMODE) == O_RDONLY);
    ASSERT(!(flags & O_CLOEXEC));

    return EXIT_SUCCESS;
}
